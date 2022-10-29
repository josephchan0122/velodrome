from rest_framework.metadata import BaseMetadata


class BlankMetadata(BaseMetadata):
    def determine_metadata(self, request, view):
        return {}
