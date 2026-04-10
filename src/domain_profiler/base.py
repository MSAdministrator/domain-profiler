from domain_profiler.logger import LoggingBase


class Base(metaclass=LoggingBase):
    extensions = [
        'zip',
        'exe',
        'msi',
        'mp4',
        'ps1',
        'txt',
        'log',
        'apk',
        'dll',
        'bin',
        'docx',
        'tmp',
        'gz',
        'xlsx',
        'xls',
        'ppt',
        'pptx',
        'sh',
        'pdf'
    ]
