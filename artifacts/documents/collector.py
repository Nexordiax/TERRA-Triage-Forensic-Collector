from pathlib import Path


def classify(path):
    if Path(path).suffix.lower() in {'.pdf', '.doc', '.docx', '.odt', '.rtf', '.txt',
                                   '.xls', '.xlsx', '.ods', '.ppt', '.pptx', '.odp', '.csv'}:
        return 'Documents'
