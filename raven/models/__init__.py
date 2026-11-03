import importlib
import pkgutil

_all_imported = False


def import_all_models():
    """Import every model module, so SQLAlchemy can resolve all the relationships named as
    strings (EUD.stats -> "EUDStats", ...).

    The first query configures every mapper at once, and a relationship whose target class
    hasn't been imported yet fails it for good ("expression 'EUDStats' failed to locate a
    name"), for every later query in the process too. Most models only get imported by the
    blueprints, so code that can run before those are (scheduled jobs: the scheduler starts in
    init_extensions, before create_app registers the blueprints) must call this first."""
    global _all_imported
    if _all_imported:
        return

    import sqlalchemy.exc
    from flask_security.models import fsqla_v3 as fsqla

    from raven.extensions import db

    # user/role need Flask-Security's tables; already done in every app (an error then)
    try:
        fsqla.FsModels.set_db_info(db)
    except sqlalchemy.exc.InvalidRequestError:
        pass

    for module in pkgutil.iter_modules(__path__):
        importlib.import_module(f"{__name__}.{module.name}")
    _all_imported = True
