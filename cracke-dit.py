import sys, os, argparse, itertools, time
from threading import Thread, Event

import ntds_parser as ntds, outputs
from database import HashDatabase


BANNER = """\033[91m
                        __                  ___ __ 
  ______________ ______/ /_____        ____/ (_) /_
 / ___/ ___/ __ `/ ___/ //_/ _ \______/ __  / / __/
/ /__/ /  / /_/ / /__/ ,< /  __/_____/ /_/ / / /_  
\___/_/   \__,_/\___/_/|_|\___/ \033[90mv1.0\033[0m\033[91m \__,_/_/\__/  
        \033[0m@darkp0rt\n"""


if __name__ == "__main__":
    print(BANNER)
    available_outputs = ", ".join(outputs.discover_outputs().keys())
    parser = argparse.ArgumentParser(add_help=True, description="crack-dit makes it easier to perform password "
                                                                "audits against Windows-based corporate environments.",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--database-name", default="db.json", action="store", help="Name of the database file to store")

    group = parser.add_argument_group("1. Cracking", "cracke-dit can take your raw ntds.dit and SYSTEM hive "
                                                              "and turn them in to a user:hash file for cracking "
                                                              "within your favourite password cracker")
    group.add_argument("--system", action="store", help="(local) SYSTEM hive to parse")
    group.add_argument("--ntds", action="store", help="(local) ntds.dit file to parse")
    group.add_argument("--username", action="store", help="(remote) Domain Admin username to connect to the target")
    group.add_argument("--password", action="store", help="(remote) Domain Admin username to connect to the target")
    group.add_argument("--target", action="store", help="(remote) IP address of the Domain Contoller to connect to")
    group.add_argument("--out", action="store", help="File to write user:hash to")
    group.add_argument("--no-history", action="store_false", dest="historic", default=True,
                        help="Set to disable historic password processing. Will speed up significantly.")

    group = parser.add_argument_group("2. Reporting", "use these options to process a hash:password file from "
                                                        "your favourite password cracker")
    group.add_argument("--pot", action="store", help="Your .pot file in hash:password format.")
    group.add_argument("--domain", action="store", help="Full domain FQDN, i.e. acme.local.")
    group.add_argument("--only-enabled", action="store_true", dest="only_enabled", default=False,
                        help="Only show passwords for enabled accounts.")
    group.add_argument("--only-users", action="store_true", dest="only_users", default=False,
                        help="Only show user accounts, i.e. ignore computer accounts.")
    group.add_argument("--output", action="store", default="stdout",
                        help="Output module to visualise the data: %s " % available_outputs)
    args = parser.parse_args()

    local = (args.system and args.ntds)
    remote = (args.username and args.password and args.target)

    if local or remote:
        domain, hashes = ntds.process_local(args.system, args.ntds, args.historic) if local else ntds.process_remote(args.username, args.password, args.target, args.historic)
        ntlm_file = args.out or "{0}.hashes.ntlm".format(domain)

        with HashDatabase(args.database_name, domain, raise_if_table_doesnt_exist=False) as db:
            with open(ntlm_file, "w+") as out:
                for hash in hashes:
                    out.write("%s:%s%s" % (hash["username"], hash["ntlmhash"], os.linesep))
                    db.insert(hash["username"], hash["ntlmhash"], hash["enabled"] if "enabled" in hash else None, hash["historic"] if "historic" in hash else None)

        print("Found {} hashes for '{}', available at {}. Run them through your favourite password cracker and re-run cracke-dit with --pot - see README for tips!".format(len(hashes), domain, ntlm_file))
    elif args.pot and args.domain:
        def update(stopper):
            spinner = itertools.cycle(['-', '/', '|', '\\'])

            while not stopper.is_set():
                sys.stdout.write("[" + spinner.next() + "] Processing...   \r")
                sys.stdout.flush()
                time.sleep(0.2)

        stopper = Event()
        spinner = Thread(target=update, args=(stopper,))
        spinner.start()

        with HashDatabase(args.database_name, args.domain,
                          raise_if_table_doesnt_exist=True, only_enabled=args.only_enabled, only_users=args.only_users) as db:
            with open(args.pot, "r") as pot:
                for line in pot:
                    line = line.rstrip("\r\n").replace("$NT$", "")  # $NT$ for John
                    hash, password = line.split(":")
                    db.update_hash_password(hash, password)

            outputs.get_output_by_name(args.output).run(db, args)
            stopper.set()
            spinner.join()
    else:
        parser.print_help()
