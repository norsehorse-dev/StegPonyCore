"""Rebuilds crates/stegpony-core/src/text/en.txt, the English dictionary list.

Needs wordfreq 3.1.1, spylls, and the en_US Hunspell dictionary from Debian's
hunspell-en-us 1:2020.12.07 (at /usr/share/hunspell/en_US.{aff,dic}). Usage:

    python3 tools/wordlist/make_list.py > crates/stegpony-core/src/text/en.txt

The list is part of format v1: once released it never changes, and this script is
the record of how it was chosen, not a way to change it.
"""
import os
import re
import sys

from spylls.hunspell import Dictionary
from wordfreq import top_n_list

HERE = os.path.dirname(os.path.abspath(__file__))

# Words autocorrect may rewrite: contraction lookalikes.
CONTRACTIONS = set("""its ill wed well were shell shed lets wont cant hell hes shes whos youre
theyre ive hed isnt dont didnt doesnt wasnt arent aint couldnt wouldnt shouldnt hadnt hasnt
havent weve youve youll youd theyll theyd thats whats wheres heres theres wouldve couldve
shouldve werent mustnt neednt id im""".split())

# Spellings that differ between US and UK keyboards.
VARIANTS = set("""gray grey plow mold molds molding moldy aging judgment judgments skeptic
skeptical skeptics cozy tire tires catalog catalogs analog dialog defense defenses offense
offenses license licensed licenses pretense practise aluminum mustache pajamas fetus maneuver
maneuvers ax artifact artifacts enroll enrolled fulfill fulfilled skillful willful mom moms mum
donut donuts whiskey jewelry jewellery counselor counselors marvelous woolen center centers
centered theater theaters meter meters fiber fibers liter liters somber saber specter luster
caliber meager plowed programme cheque curb curbs storey draught tyre kerb sulfur sulphur vise""".split())
OR_STEMS = """color colour favor honor humor labor neighbor flavor harbor behavior rumor vapor armor
odor valor savior vigor rigor tumor parlor endeavor clamor splendor candor ardor fervor
glamor""".split()
OUR_OK = {"four", "hour", "hours", "your", "our", "ours", "tour", "tours", "pour", "poured",
          "pouring", "sour", "flour", "tourist"}
L_STEMS = ("travel|cancel|label|model|fuel|total|level|signal|marvel|counsel|channel|dial|"
           "duel|equal|jewel|panel|pedal|quarrel|rival|shovel|tunnel")

# Families removed wholesale (any word starting with these), on top of excluded.txt.
STEMS = """kill murder rape bomb shoot gun weapon terror suicid drug cocaine heroin sex porn nude
naked fuck shit bitch damn crap piss dick cock pussy whore slut nazi hitler jihad isis militar
army war soldier attack assault violen abus victim death dead dying corpse blood bleed cancer
tumor virus infect diseas pandem covid poison toxic explos arrest prison jail police crim fraud
scam hack steal stole thief theft robb kidnap hostag ransom racis slave gay lesbian transg bisex
queer religio church christ jesus bible islam muslim jew hindu buddh prayer pray god lord satan
devil hell elect vote politic democra republic liberal conserv senat congress president presiden
trump biden obama secret hidden hiding conceal encrypt decrypt cipher password stealth covert
spy spies decoy steg sneak smuggl cartel mafia gang riot protest missile nuclear weapon rifle
pistol grenade sniper bullet ammo knife stab hang lynch execut tortur genocid massacr""".split()

ABBREVIATIONS = set("""etc inc ltd vol iii com org www http html url app apps lol omg btw tbh
idk wtf usa uk usd jan feb mar apr jun jul aug sep sept oct nov dec mon tue wed thu fri sat sun
mrs mr dr st nd rd th ok okay yeah yes hey hello bye haha""".split())


def rejected(w, excluded):
    if w in CONTRACTIONS or w in VARIANTS or w in ABBREVIATIONS or w in excluded:
        return True
    if re.search(r"(iz|yz)(e|es|ed|ing|ation|ations|er|ers)$", w):
        return True
    if any(w.startswith(s) for s in OR_STEMS):
        return True
    if re.search(r"our(s|ed|ing|ite|ites|ful|able)?$", w) and w not in OUR_OK:
        return True
    if re.search(r"(" + L_STEMS + r")(ed|ing|er|ers)$", w):
        return True
    if w.endswith("ogue"):
        return True
    return any(w.startswith(s) for s in STEMS)


def main():
    hunspell = Dictionary.from_files("/usr/share/hunspell/en_US")
    excluded = set(open(os.path.join(HERE, "excluded.txt")).read().split())
    out, seen = [], set()
    for w in top_n_list("en", 40000):
        if w in seen or not re.fullmatch(r"[a-z]{3,9}", w):
            continue
        seen.add(w)
        if not hunspell.lookup(w) or rejected(w, excluded):
            continue
        out.append(w)
        if len(out) == 4096:
            break
    if len(out) != 4096:
        sys.exit("not enough words")
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
