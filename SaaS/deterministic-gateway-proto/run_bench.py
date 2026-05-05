import asyncio
from app.regulatory.benchmark import run_benchmark
from app.database import init_db

async def main():
    await init_db()
    summary = await run_benchmark()
    import json
    print(json.dumps(summary.dict(), indent=2))

if __name__ == "__main__":
    asyncio.run(main())
