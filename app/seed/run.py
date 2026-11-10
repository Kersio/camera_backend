import asyncio

from app.core.database import AsyncSessionFactory
from app.seed.rbac import seed_rbac


async def main() -> None:
    async with AsyncSessionFactory() as session:
        await seed_rbac(session)

    print("RBAC roles and permissions seeded successfully.")


if __name__ == "__main__":
    asyncio.run(main())