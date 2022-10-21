import dataclasses
import sys
import boto3


@dataclasses.dataclass
class AccessFile:
    aws_access_key_id: str
    aws_secret_access_key: str
    mfa_serial_arn: str
    login_session_seconds: int


def get_encrypted_access_file(name):
    pass


def decrypt_access_file() -> AccessFile:
    pass


def encrypt_access_file(accessfile: AccessFile):
    pass


def exists_encrypted_access_file(name: str) -> bool:
    return get_encrypted_access_file(name) is True


def login_to_aws(name: str):
    mfa = input("MFA: ")
    pass


def setup_encrypted_access_file(name: str):
    pass


def main():
    if len(sys.argv) < 2:
        print("You must enter a name parameter behind aws_login.")
        return
    name = sys.argv[1]
    if exists_encrypted_access_file(name):
        login_to_aws(name)
    else:
        setup_encrypted_access_file(name)
        login_to_aws(name)


if __name__ == '__main__':
    main()
