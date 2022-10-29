from rest_framework_csv.renderers import CSVStreamingRenderer


class TSVStreamingRenderer(CSVStreamingRenderer):
    media_type = 'text/tab-separated-values'
    format = 'tsv'
    writer_opts = {
        'dialect': 'excel-tab'
    }
