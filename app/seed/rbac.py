from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Permission, Role
from app.models.associations import role_permissions

PERMISSIONS = [
    ("users.create", "Create users"),
    ("users.read", "View users"),
    ("users.update", "Update users"),
    ("users.delete", "Delete users"),
    ("cameras.read", "View cameras"),
    ("cameras.manage", "Manage cameras"),
    ("incidents.read", "View incidents"),
    ("incidents.acknowledge", "Acknowledge incidents"),
    ("incidents.close", "Close incidents"),
    ("reports.read", "View reports"),
    ("reports.export", "Export reports"),
    ("system.manage", "Manage system settings"),
]


ROLES = {
    "admin": {
        "description": "System administrator",
        "permissions": [permission[0] for permission in PERMISSIONS],
    },
    "operator": {
        "description": "Video surveillance operator",
        "permissions": [
            "cameras.read",
            "incidents.read",
            "incidents.acknowledge",
            "incidents.close",
            "reports.read",
        ],
    },
    "security_guard": {
        "description": "Security guard",
        "permissions": [
            "cameras.read",
            "incidents.read",
            "incidents.acknowledge",
        ],
    },
    "security_manager": {
        "description": "Security manager",
        "permissions": [
            "cameras.read",
            "incidents.read",
            "incidents.acknowledge",
            "incidents.close",
            "reports.read",
            "reports.export",
        ],
    },
}


async def seed_rbac(session: AsyncSession) -> None:
    permissions_by_code: dict[str, Permission] = {}

    # Создаём отсутствующие разрешения.
    for code, description in PERMISSIONS:
        result = await session.execute(
            select(Permission).where(Permission.code == code)
        )
        permission = result.scalar_one_or_none()

        if permission is None:
            permission = Permission(
                code=code,
                description=description,
            )
            session.add(permission)
            await session.flush()

        permissions_by_code[code] = permission

    roles_by_name: dict[str, Role] = {}

    # Создаём отсутствующие роли.
    for role_name, role_data in ROLES.items():
        result = await session.execute(
            select(Role).where(Role.name == role_name)
        )
        role = result.scalar_one_or_none()

        if role is None:
            role = Role(
                name=role_name,
                description=role_data["description"],
            )
            session.add(role)
            await session.flush()

        roles_by_name[role_name] = role

    # Формируем связи ролей с разрешениями.
    links = []

    for role_name, role_data in ROLES.items():
        role = roles_by_name[role_name]

        for code in role_data["permissions"]:
            permission = permissions_by_code[code]

            links.append(
                {
                    "role_id": role.id,
                    "permission_id": permission.id,
                }
            )

    # Добавляем только отсутствующие связи.
    if links:
        statement = (
            insert(role_permissions)
            .values(links)
            .on_conflict_do_nothing(
                index_elements=[
                    role_permissions.c.role_id,
                    role_permissions.c.permission_id,
                ]
            )
        )

        await session.execute(statement)

    await session.commit()