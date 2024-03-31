import asyncio
import socket
import ftplib
import json
from typing import Iterable


class Result:
    def __init__(self, **kwargs):
        self.addr = kwargs.get("addr", None)
        self.status = kwargs.get("status", None)
        self.banner = kwargs.get("banner", None)
        self.anon_login = kwargs.get("anon_login", None)
        self.user = kwargs.get("user", None)
        self.password = kwargs.get("password", None)
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
            print("Trying credentials from list", end="")
            i = 0
            cred = next(wordlist, None)
            while cred:
                print(".", end="")
                tasks = []
                for j in range(0, 16):
                    i += 1
                    tasks.append(asyncio.create_task(check_cred(addr, cred)))
                    cred = next(wordlist, None)
                    if not cred:
                        break

                task_ret = await asyncio.wait(fs={*tasks}, return_when=asyncio.ALL_COMPLETED)
                valid_cred = [x for x in task_ret if x]
                if valid_cred:
                    user, password = valid_cred[0]
                    break
            print("")

        if not user:
            return Result(addr=addr, status="unauthorized", banner=banner, anon_login=False)

    return Result(addr=addr, status="ok", banner=banner, anon_login=anon_login,
                  user=user, password=password)


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
