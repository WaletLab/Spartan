from typing import Generator, Callable, Any, Optional
import asyncio


async def check_all_entries(f: Callable[[Any, tuple[str, str]], Optional[Any]], addr: Any, entries: Generator, sleep: int = 0, pool_size: int = 32, break_on_first: bool=True) -> list[Any]:
    result = []
    entry = next(entries, None)
    while entry:
        tasks = []
        for i in range(0, pool_size):
            tasks.append(asyncio.create_task(f(addr, entry)))
            entry = next(entries)
            if not entry:
                break

            task_ret, _ = await asyncio.wait(fs={*tasks}, return_when=asyncio.ALL_COMPLETED)
            valid_cred = [x.result() for x in task_ret if x]
            if valid_cred:
                if break_on_first:
                    return valid_cred
                else:
                    result.extend(valid_cred)
    return result
