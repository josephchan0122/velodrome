from django.conf import settings
from django.core.files.storage import get_storage_class
from storages.backends.s3boto3 import S3Boto3Storage

storage_class = get_storage_class()
if storage_class is S3Boto3Storage:
    private_storage = storage_class(
        bucket=settings.PRIVATE_BUCKET_NAME, acl="private"
    )
else:
    private_storage = storage_class()
