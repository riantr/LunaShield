if not user.is_admin:
    raise PermissionError()
