def to_string(data):
    if isinstance(data, unicode):
        return str(data)
    elif isinstance(data, str):
        return data
    else:
        return str(data)
