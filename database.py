import itertools, string
from datetime import datetime
from random import shuffle

import zxcvbn
from tinydb import TinyDB, Query
from tinydb.middlewares import CachingMiddleware
from tinydb_serialization import Serializer, SerializationMiddleware

BLANK_NTLMHASH = "31d6cfe0d16ae931b73c59d7e0c089c0"


class DateTimeSerializer(Serializer):
    OBJ_CLASS = datetime

    def encode(self, obj):
        return obj.strftime("%Y-%m-%dT%H:%M:%S")

    def decode(self, s):
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S")


class HashDatabase:
    def __init__(self, db_name, domain, raise_if_table_doesnt_exist=True, only_enabled=False, only_users=False):
        self.db = None
        self.table = None
        self.only_enabled = (Query().enabled.exists() if only_enabled else Query().ntlmhash.exists()) & ( Query().enabled == True if only_enabled else Query().ntlmhash.exists())
        self.only_users = (Query().username.exists() if only_users else Query().ntlmhash.exists()) & (Query().username.test(lambda v: not v.endswith("$")) if only_users else Query().ntlmhash.exists())

        serialization = SerializationMiddleware()
        serialization.register_serializer(DateTimeSerializer(), "datetime")

        self.db = TinyDB(db_name, storage=CachingMiddleware(serialization))

        if raise_if_table_doesnt_exist and domain not in self.db.tables():
            raise ValueError("Hashes for domain '{}' do not exist in database.".format(domain))

        self.table = self.db.table(domain)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.db.close()

    @property
    def counts(self):
        total = self.table.count(self.only_enabled & self.only_users)
        local_users = self.table.count((~ Query().historic.exists()) & (Query().username.test(lambda v: "\\" not in v and not v.endswith("$"))) & self.only_users)
        domain_users = self.table.count((~ Query().historic.exists()) & (Query().username.test(lambda v: "\\" in v and not v.endswith("$"))) & self.only_users)
        computers = self.table.count(Query().username.test(lambda v: v.endswith("$")))

        return total, local_users, domain_users, computers

    @property
    def user_counts(self):
        enabled_users = self.table.search((Query().enabled == True) & (Query().username.test(lambda v: not v.endswith("$"))))
        disabled_users = self.table.search((Query().enabled == False) & (Query().username.test(lambda v: not v.endswith("$"))))

        return len(enabled_users), len(disabled_users)

    @property
    def password_stats(self):
        cracked = self.table.count((Query().password.exists()) & (Query().password != "") & self.only_users & self.only_enabled)
        blank = self.table.count(Query().ntlmhash == BLANK_NTLMHASH)
        historic = self.table.count((Query().historic.exists()) & self.only_enabled & self.only_users)

        return cracked, blank, historic

    @property
    def all_passwords(self):
        results = self.table.search((Query().password.exists()) & (Query().password != "") & self.only_users & self.only_enabled)

        return [(result["password"], zxcvbn.password_strength(result["password"])["score"]) for result in results]

    @property
    def password_char_stats(self):
        alphanum = string.ascii_letters + string.digits
        only_alpha = self.table.count(Query().password.test(lambda p: p != "" and all(c in alphanum for c in p)))
        with_special = self.table.count(Query().password.test(lambda p: p != "" and any(c not in alphanum for c in p)))

        return only_alpha, with_special

    def get_top_passwords(self, sortby, reverse=True, limit=10):
        results = sorted(self.table.search((Query().password.exists()) & self.only_users & self.only_enabled), key=lambda r: r["password"])
        passwords = ((password, len(list(count))) for password, count in itertools.groupby(results, lambda r: r["password"]))

        return sorted(list(
            (password, count, zxcvbn.password_strength(password)["score"], self.__get_users_with_password(password))
                for password, count in passwords)[:limit], key=sortby, reverse=reverse)

    def get_passwords_where(self, where):
        return self.table.search((Query().password.exists()) & (Query().password.test(where)))

    def update_hash_password(self, hash, password):
        self.table.update({"ntlmhash": hash.strip(), "password": password.strip(), "updated": datetime.now()}, Query().ntlmhash == hash)

    def insert(self, username, ntlmhash, enabled, historic):
        u = username.strip()
        eh_key = "historic" if not enabled and historic else "enabled"
        eh_val = historic if not enabled and historic else enabled

        self.table.insert({"username": u, "ntlmhash": ntlmhash.strip(), eh_key: eh_val, "created": datetime.now()})

    def __get_users_with_password(self, password):
        users = self.table.search(
            (Query().password.exists()) & (Query().username.exists()) & (Query().password == password)
            & self.only_users & self.only_enabled
        )
        shuffle(users)

        return users
