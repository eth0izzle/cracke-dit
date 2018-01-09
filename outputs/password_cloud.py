import platform

from wordcloud import WordCloud
import matplotlib as mpl


def add_args(parser):
    pass


def run(db, args):
    if platform.system() == "Darwin":
        mpl.use("TkAgg")

    import matplotlib.pyplot as plt

    title = "Top reused passwords for {}".format(args.domain)
    passwords = db.all_passwords

    wc = WordCloud(background_color="black", width=1280, height=800, margin=5, max_words=1000, color_func=__get_password_color(passwords))
    wc.generate(" ".join([password for password, score in passwords]))

    plt.title(title)
    plt.imshow(wc, interpolation="nearest", aspect="equal")
    plt.axis("off")
    plt.show()


def __get_password_color(passwords):
    colormap = {0: "0, 50%, 50%", 1: "25, 50%, 50%", 2: "55, 80%, 50%", 3: "120, 50%, 50%", 4: "0, 100%, 100%"}

    def get_color(word, font_size, position, orientation, random_state=None, **kwargs):
        scores = [score for password, score in passwords if password == word]
        score = next(iter(scores or []), 0)

        return "hsl({})".format(colormap[score])

    return get_color
