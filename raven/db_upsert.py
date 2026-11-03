"""INSERT ... ON CONFLICT DO NOTHING for the rows the CoT parser and EUD handlers create on
first sight (chatrooms, chatroom members, teams, EUDs).

Those used to be "add, commit, catch IntegrityError, roll back". That works, but every time a
known chatroom/team/device came through PostgreSQL logged the rejected insert as an ERROR
("duplicate key value violates unique constraint ..."), and several processes (each EudHandler
connection is its own process) race to create the same row. Letting the database skip the
existing row is race-free and logs nothing.
"""

import sqlalchemy.exc


def insert_ignore(session, model, values, index_elements):
    """Insert one row of model unless a row with the same index_elements (a primary key or
    unique constraint) exists. Returns True if this call inserted it. Does not commit."""
    table = model.__table__
    dialect = session.get_bind().dialect.name

    if dialect in ("postgresql", "sqlite"):
        if dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert
        else:
            from sqlalchemy.dialects.sqlite import insert

        result = session.execute(
            insert(table).values(**values).on_conflict_do_nothing(index_elements=index_elements)
        )
        return bool(result.rowcount)

    if dialect in ("mysql", "mariadb"):
        from sqlalchemy.dialects.mysql import insert

        result = session.execute(insert(table).values(**values).prefix_with("IGNORE"))
        return bool(result.rowcount)

    # Anything else: a savepoint, so a duplicate only undoes this insert
    try:
        with session.begin_nested():
            session.execute(table.insert().values(**values))
        return True
    except sqlalchemy.exc.IntegrityError:
        return False
