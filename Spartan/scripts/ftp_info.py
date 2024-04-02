import asyncio
import socket
import ftplib
import json
from typing import Iterable

from ..lib.helpers.bruteforce_async import check_all_entries


class Result:
    def __init__(self, **kwargs):
        self.addr = kwargs.get("addr", None)
        self.status = kwargs.get("status", None)
        self.banner = kwargs.get("banner", None)
        self.anon_login = kwargs.get("anon_login", None)
        self.user = kwargs.get("user", None)
        self.password = kwargs.get("password", None)
        self.ls = kwargs.get("ls", None)
        self.error_info = kwargs.get("error_info", None)


async def check_cred(addr: str, cred: tuple[str, str]) -> tuple[str, str] | None:
    ftp = ftplib.FTP(addr)
    try:
        ftp.login(cred[0], cred[1])
    except ftplib.error_perm:
        return None
    ftp.close()
    return cred


async def scan(addr: str, wordlist: Iterable = None) -> Result:
    try:
        ftp = ftplib.FTP(addr)
    except socket.error as exc:
        return Result(addr=addr, status="error", error_info=str(exc))

    banner = ftp.getwelcome()

    user = None
    password = None

    try:
        ftp.login()
        anon_login = True
    except ftplib.error_perm:
        anon_login = False

        if wordlist:
            print("Trying credentials from list")
            valid_cred = await check_all_entries(check_cred, addr, wordlist)
            if valid_cred:
                user, password = valid_cred[0]
            print("Found valid credentials:", user+":"+password)

        if not user:
            return Result(addr=addr, status="unauthorized", banner=banner, anon_login=False)

    ls = []
    ftp.dir(ls.append)
    ls = "\n".join(ls)

    return Result(addr=addr, status="ok", banner=banner, anon_login=anon_login,
                  user=user, password=password, ls=ls)


async def main():
    host = ""
    wordlist = ""
    with open(wordlist) as f:
        cred = (ln.strip().split(":") for ln in f.readlines())
    result = await scan(host, cred)
    almost_json = {}
    for x in [y for y in result.__dict__ if y[0] != "_"]:
        almost_json[x] = getattr(result, x)
        # print(x, "=", getattr(result, x))
    print(json.dumps(almost_json))
    # ???

if __name__ == "__main__":
    asyncio.run(main())
