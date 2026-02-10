import argparse
import asyncio
import getpass
import sys

from sqlalchemy.exc import IntegrityError

from app.db.session import AsyncSessionLocal
from app.models.user import User
from app.services.auth import hash_password


async def add_user(username: str):
    password = getpass.getpass("[*] Enter password: ")
    password_confirm = getpass.getpass("[*] Confirm password: ")

    if password != password_confirm:
        print("[-] Passwords do not match")
        sys.exit(1)

    user = User(username=username, hashed_password=hash_password(password))

    async with AsyncSessionLocal() as session:
        try:
            session.add(user)
            await session.commit()
            print(f"[+] User '{username}' created successfully")
        except IntegrityError:
            print(f"[-] User '{username}' already exists")
            sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Add a new user to onewAy")
    parser.add_argument(
        "-u", "--username", help="Username of the new user", required=True
    )
    args = parser.parse_args()
    asyncio.run(add_user(args.username))
