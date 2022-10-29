from django.apps import apps as django_apps
from django.core import serializers
from django.db import models, transaction

from .const import ADV_DEVICE_TABLE, DJANGO_APP_NAME


def dump_models(file_path: str):
    """Save data of models to file.
    envdir envdir python manage.py shell -c 'from velodrome.advanced_devices.script import dump_models; dump_models("/tmp/adv_devices.json")'  # noqa
    """
    model_cls_list = [
        cls
        for cls in django_apps.get_models()
        if cls._meta.app_label == DJANGO_APP_NAME
    ]
    org_cls = django_apps.get_model("lock8", "Organization")
    lock_cls = django_apps.get_model("lock8", "Lock")
    data = []
    for model in model_cls_list:
        data.extend(model.objects.all().iterator())

    used_organization = set()
    for record in data:
        org_id = getattr(record, "organization_id", None)
        if org_id:
            used_organization.add(org_id)

    data.extend(
        org_cls.objects.filter(
            pk__in=used_organization
        ).iterator()
    )
    locks = lock_cls.objects.filter(
        organization__pk__in=used_organization
    ).select_related(
        "shared_secret"
    ).iterator()

    for lock in locks:
        data.append(lock)
        if lock.shared_secret:
            data.append(lock.shared_secret)

    dump_data = serializers.serialize("json", data)
    with open(file_path, "w") as of:
        of.write(dump_data)

    print(len(data), "records in", file_path)


def save_record(
    record: models.Model, all_records: list, ref_records: dict
):
    """Save record recursively.
    """
    fields = record._meta.fields
    for field in fields:
        if field.name == "organization":
            continue

        if not isinstance(field, models.ForeignKey):
            continue

        ref_cls = field.related_model
        ref_id = getattr(record, f"{field.name}_id")
        if not ref_id:
            continue

        if (ref_id, ref_cls) not in ref_records:
            # create ref record
            for ref_rec in all_records:
                if ref_rec.pk == ref_id and isinstance(ref_rec, ref_cls):
                    save_record(ref_rec, all_records, ref_records)
                    break

        new_ref_rec = ref_records[ref_id, ref_cls]
        setattr(record, field.name, new_ref_rec)

    old_pk = (record.pk or record.id)
    record.pk = record.id = None
    record.save()
    ref_records[old_pk, record._meta.model] = record


@transaction.atomic
def restore_dump(file_path: str, clear: bool = False):
    """Restore dump.
    envdir envdir python manage.py shell -c 'from velodrome.advanced_devices.script import restore_dump; restore_dump("/tmp/adv_devices.json", True)'  # noqa
    """
    org_cls = django_apps.get_model("lock8", "Organization")
    lock_cls = django_apps.get_model("lock8", "Lock")
    shared_secret_cls = django_apps.get_model("lock8", "SharedSecret")
    organizations = {}
    records = []
    locks = {}
    shared_secrets = {}
    used_organization = set()
    used_cls = set()
    with open(file_path) as data_file:
        for src_item in serializers.deserialize("json", data_file):
            record = src_item.object
            rec_cls = record.__class__
            if rec_cls._meta.db_table == org_cls._meta.db_table:
                organizations[record.id] = (record.name, record.parent_id)
            elif rec_cls._meta.db_table == lock_cls._meta.db_table:
                locks[record.serial_number] = record
            elif rec_cls._meta.db_table == shared_secret_cls._meta.db_table:
                shared_secrets[record.id] = [record, False]
            else:
                used_cls.add(rec_cls)
                records.append(record)
                if hasattr(rec_cls, "organization_id"):
                    used_organization.add(record.organization_id)

    print("New records:", len(records))
    # prepare organizations
    current_organizations = {}
    no_organizations = []
    for src_org_id in used_organization:
        src_name, src_parent_id = organizations[src_org_id]
        org_filter = {"name": src_name}
        src_parent_name = ""
        if src_parent_id:
            src_parent_name, _ = organizations[src_parent_id]
            org_filter["parent__name"] = src_parent_name

        org = org_cls.objects.filter(**org_filter).first()
        # you should create organizations at first
        if org:
            current_organizations[src_org_id] = org
        else:
            no_organizations.append(
                f"Organization with name {src_name} "
                f"(parent: {src_parent_name or 'none'}) doesn't exist in db"
            )

    if no_organizations:
        print(*no_organizations)
        raise ValueError("Create organizations")

    # clear current state
    if clear:
        assert lock_cls not in used_cls and org_cls not in used_cls
        deleted_total = 0
        for model_cls in used_cls:
            count, *_ = model_cls.objects.all().delete()
            deleted_total += count

        print("Deleted:", deleted_total)

    ref_records = {}

    for record in records:
        if hasattr(record, "organization_id") or hasattr(record, "organization"):  # noqa
            src_org = record.organization_id
            record.organization = current_organizations[src_org]

        save_record(record, records, ref_records)

        if record._meta.db_table == ADV_DEVICE_TABLE:
            sn = record.serial_number
            lock_record = lock_cls.objects.filter(
                serial_number=sn
            ).first()
            if lock_record is None:
                lock_record = locks.get(sn)
                if not lock_record:
                    continue

                lock_record.pk = lock_record.id = None
                lock_record.public_tracking = None
                lock_record.private_tracking = None
                if lock_record.shared_secret_id:
                    shared_secret, updated = shared_secrets.get(
                        lock_record.shared_secret_id
                    )
                    if not updated:
                        shared_secret.pk = shared_secret.id = None
                        shared_secret.save()
                        shared_secrets[lock_record.shared_secret_id][1] = True

                    lock_record.shared_secret = shared_secret

                if lock_record.owner_id:
                    lock_record.owner = record.organization.owner

            lock_record.organization = record.organization
            lock_record.save()

    print("done")
