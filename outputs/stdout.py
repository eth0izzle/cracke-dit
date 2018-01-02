# coding: utf-8

from __future__ import division
import sys, calendar
from collections import OrderedDict

import zxcvbn

END = "\033[0m"
WHITE = "\033[99m"
GREEN = "\033[92m"
YELLOW = "\033[96m"
ORANGE = "\033[93m"
RED = "\033[91m"
DIM = "\033[90m"


def run(db, args):
    total, local_users, domain_users, computers = db.counts

    print("cracke-dit report for {}\n".format(args.domain))
    print("Local / Domain users:\t{}/{}".format(local_users, domain_users))

    if not args.only_enabled:
        print("Enabled / disabled users:\t{}/{}".format(*db.user_counts))

    if not args.only_users:
        print("Computer accounts:\t{}\t{:.2f}%".format(computers, (computers / total) * 100))

    cracked, blank, historic = db.password_stats
    print("Passwords cracked:\t{}/{}\t{:.2f}%".format(cracked, total, (cracked / total) * 100))
    print("Historic passwords:\t{}\t{:.2f}%".format(historic, (historic / total) * 100))

    only_alpha, with_special = db.password_char_stats
    print("Only alphanumeric:\t{}\t{:.2f}%".format(only_alpha, (only_alpha / total) * 100))
    print("With 'special char':\t{}\t{:.2f}%".format(with_special, (with_special / total) * 100))

    headers = ["Password", "Length", "Count", "Score", "Users"]
    fmt_lambda = lambda password, count, score, users: [password, len(password), count, __coloured_score(score), __process_users(users)]

    take_top = 10
    top_passwords = db.get_top_passwords(sortby=lambda (password, count, score, users): count, reverse=True, limit=take_top)
    __print_table(title="Top {} Passwords (by use)".format(take_top), headers=headers, align=[">", "<", "<", "<", ""],
                  values=top_passwords, format=fmt_lambda)

    take_top = 5
    bad_pass = db.get_top_passwords(sortby=lambda (password, count, score, users): (zxcvbn.password_strength(password)["score"], len(password)), reverse=False, limit=take_top)
    __print_table(title="Top {} Worst Passwords".format(take_top), headers=headers,
                  align=[">", "<", "<", "<", ""], values=bad_pass, format=fmt_lambda)

    __graph_passwords_containing("Months", db, OrderedDict([(calendar.month_name[m], 0) for m in range(1, 13)]))
    __graph_passwords_containing("Days", db, OrderedDict([(calendar.day_name[d], 0) for d in range(0, 7)]))


def __print_table(title, headers, align, values, format):
    fmt = "".join(["{:" + align[headers.index(x)] + str(int(len(x)*1.75)) + "}\t".expandtabs() for x in headers])
    print("\n{}\n{}\n".format(title, "="*len(title)))
    print(fmt.format(*headers))
    print(fmt.format(*["-"*len(header) for header in headers]))

    for item in values:
        print(fmt.format(*format(*item)))


def __coloured_score(score):
    colormap = {0: RED, 1: ORANGE, 2: YELLOW, 3: GREEN, 4: WHITE}
    return "{}{:<8}{}".format(colormap[score], score, END)


def __process_users(users):
    usernames = []

    for user in users:
        uname = user["username"]

        if "historic" in user:
            usernames.append("{}{}{}".format(DIM, uname, END))
        elif "enabled" in user and not user["enabled"]:
            usernames.append("{}{}{}".format(RED, uname, END))
        else:
            usernames.append("{}{}{}".format(GREEN, uname, END))

    return ", ".join(usernames)


def __graph_passwords_containing(title, db, list):
    for row in db.get_passwords_where(lambda password: password != ""):
        for key in list:
            if key.lower() in row["password"].lower():
                list[key] += 1

    if any(val for val in list.values()):
        print("\nPasswords Containing {0}\n==========================\n".format(title))
        __print_graph(list.keys(), list.values())


def __print_graph(labels, data):
    width = 50
    val_min = min(data)
    val_max = max(data)
    normalised = data if val_max < width else [(_v - val_min) * (width / float(val_max - val_min)) for _v in data]

    for i in range(len(labels)):
        value = data[i]
        blocks = int(normalised[i])

        sys.stdout.write("{:>15}: ".format(labels[i]))
        if blocks < 1 and (value > val_min or value > 0):
            sys.stdout.write("▏")
        else:
            for _ in range(blocks):
                sys.stdout.write("▇")

        print("{}".format(value))