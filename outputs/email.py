import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# todo: move to config file
SMTP_HOST = ""
SMTP_PORT = 587  # highly recommended to only use TLS
SMTP_USER = ""
SMTP_PASS = ""
EMAIL_TO = ""
EMAIL_SUBJECT = "Password Report For {}"


def add_args(parser):
    pass


def run(db, args):
    html = []

    html.append("<h1>Top 25 Passwords</h1>")
    top_passwords = db.get_top_passwords(sortby=lambda (password, count, score, users): (count, score, len(password)), reverse=False, limit=25)
    html.append(__table(headers=["Password", "Length", "Count", "Score", "Users"], items=top_passwords,
                        format=lambda password, count, score, users: [password, len(password), count, __get_score(score), __get_users(users)]))

    print("Sending e-mail to {}...".format(EMAIL_TO))
    smtp = smtplib.SMTP(host=SMTP_HOST, port=SMTP_PORT)
    smtp.ehlo()

    if SMTP_PORT == 587:
        smtp.starttls()

    smtp.login(SMTP_USER, SMTP_PASS)

    msg = MIMEMultipart()
    msg["To"] = EMAIL_TO
    msg["Subject"] = EMAIL_SUBJECT.format(args.domain)
    msg.attach(MIMEText("".join(html), "html"))

    smtp.sendmail("", EMAIL_TO, msg.as_string())
    smtp.quit()

    print("\nAll done!")


def __table(headers, items, format):
    strings = []

    strings.append("<table width=\"100%\">")
    strings.append("<tr>")
    strings.append("".join(["<th style=\"text-align:left\">{}</th>".format(header) for header in headers]))
    strings.append("</tr>")

    for item in items:
        strings.append("<tr>")

        for val in format(*item):
            strings.append("".join("<td>{}</td>".format(val)))

        strings.append("</tr>")

    strings.append("</table>")

    return "".join(strings)


def __get_score(score):
    colormap = {0: "red", 1: "orange", 2: "yellow", 3: "green", 4: "white"}
    return "<span style=\"color:{}\">{}</span>".format(colormap[score], score)


def __get_users(users):
    usernames = []
    span = "<span style=\"color:{};\">{}</span>"

    for user in users:
        uname = user["username"]

        if "historic" in user:
            usernames.append(span.format("grey", uname))
        elif "enabled" in user and not user["enabled"]:
            usernames.append(span.format("red", uname))
        else:
            usernames.append(span.format("green", uname))

    return ", ".join(usernames)