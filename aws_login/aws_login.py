import dataclasses
import json
import subprocess
import sys
from getpass import getpass
from pathlib import Path

import boto3
from cryptography.fernet import Fernet


@dataclasses.dataclass(frozen=True)
class AccessFile:
    aws_access_key_id: str
    aws_secret_access_key: str
    mfa_serial_arn: str
    login_session_seconds: int


def build_access_file_name(name: str) -> str:
    return f"{name}_access_file"


def build_profile_name(name: str) -> str:
    return f"{name}-temporary-access"


def get_path_to_access_file(name: str) -> Path:
    aws_path = Path.home() / '.aws'
    if not aws_path.exists():
        aws_path.mkdir()
    return aws_path / build_access_file_name(name)


def save_encrypted_access_file(name: str, access_file: AccessFile):
    key = Fernet.generate_key()
    print(f"Key: {key.decode('utf-8')}")
    print(f"Copy the key somewhere only you can access it (e.g. some password safe).")

    fernet = Fernet(key)
    access_file = json.dumps(access_file.__dict__).encode('utf-8')
    encrypted_access_file = fernet.encrypt(access_file)

    file_path = get_path_to_access_file(name)
    if file_path.exists():
        raise Exception(f'{build_access_file_name(name)} already exists in .aws directory')
    file_path.write_bytes(encrypted_access_file)
    print(f"Saved encrypted {name}_access_file to .aws directory")


def load_decrypted_access_file(name: str, key: str) -> AccessFile:
    file_path = get_path_to_access_file(name)
    if not file_path.is_file():
        raise Exception(f'{build_access_file_name(name)} is missing in .aws directory')
    encrypted_access_file = file_path.read_bytes()
    encoded_key = key.encode('utf-8')
    fernet = Fernet(encoded_key)
    access_file_json = json.loads(fernet.decrypt(encrypted_access_file).decode('utf-8'))
    return AccessFile(**access_file_json)


def exists_encrypted_access_file(name: str) -> bool:
    return get_path_to_access_file(name).is_file()


def setup_encrypted_access_file(name: str):
    print(f"No {build_access_file_name(name)} found in .aws directory. Set-up new one.")
    aws_access_key_id = input("aws_access_key_id: ")
    aws_secret_access_key = input("aws_secret_access_key: ")
    mfa_serial_arn = input("mfa_serial_arn: ")
    login_session_seconds = int(input("login_session_seconds: "))

    access_file = AccessFile(aws_access_key_id=aws_access_key_id,
                             aws_secret_access_key=aws_secret_access_key,
                             mfa_serial_arn=mfa_serial_arn,
                             login_session_seconds=login_session_seconds)
    save_encrypted_access_file(name, access_file)


def login_to_aws(name: str):
    key = getpass("Key: ")
    access_file = load_decrypted_access_file(name, key)

    mfa = input("MFA: ")

    session = boto3.session.Session(
        aws_access_key_id=access_file.aws_access_key_id,
        aws_secret_access_key=access_file.aws_secret_access_key
    )
    client = session.client("sts")
    session_token = client.get_session_token(
        DurationSeconds=access_file.login_session_seconds,
        SerialNumber=access_file.mfa_serial_arn,
        TokenCode=mfa
    )

    credentials = session_token['Credentials']
    subprocess.run(f"aws configure set aws_access_key_id {credentials['AccessKeyId']} --profile {build_profile_name(name)}")
    subprocess.run(
        f"aws configure set aws_secret_access_key {credentials['SecretAccessKey']} --profile {build_profile_name(name)}")
    subprocess.run(f"aws configure set aws_session_token {credentials['SessionToken']} --profile {build_profile_name(name)}")
    print(f"{build_profile_name(name)} configured in .aws/credentials")


def main():
    if len(sys.argv) < 2:
        print("You must enter a name parameter behind aws_login.")
        return
    name = sys.argv[1]
    if exists_encrypted_access_file(name):
        login_to_aws(name)
    else:
        setup_encrypted_access_file(name)


if __name__ == '__main__':
    main()
