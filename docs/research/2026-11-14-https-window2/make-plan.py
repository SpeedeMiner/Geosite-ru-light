#!/usr/bin/env python3
"""Freeze the first two measurement waves from the audited handoff."""
import csv
from pathlib import Path

HERE = Path(__file__).resolve().parent
with (HERE.parent / "2026-11-14-halfhour/12-next-https.tsv").open() as f:
    prior = {int(r["order"]): r for r in csv.DictReader(f, delimiter="\t")}

first = [
    ("Polpred|Полпред|Обзор СМИ", "ПОЛПРЕД, руководство указывает точный education.polpred.com"),
    ("Самсон|Samson", "САМСОН Групп"),
    ("Bitronics|Битроникс", "ООО «Битроникс»"),
    ("Online Test Pad|OnlineTestPad", "Российский оператор платформы в соглашении о регистрации"),
    ("SF Education|Современные формы образования", "ООО «Современные формы образования»"),
    ("Поток|Potok", "ООО «Поток»"),
    ("Myrtle|ООО «МИРТ»", "ООО «МИРТ»"),
    ("Наносемантика|Nanosemantics", "ООО «Лаборатория Наносемантика»"),
    ("Никта|Nikta|ООО «ЗВЕНО»", "ООО «ЗВЕНО»"),
    ("Аутлайнс|Outlines", "ООО «Аутлайнс»"),
    ("Под контролем|ПодКонтролем|ПДК", "ООО «ПДК»"),
    ("TrainingSpace|Training Space|ТренингСпэйс|Облако Груп", "ООО «Облако Груп»"),
    ("Регистр судоходства|Maritime Register of Shipping", "ФАУ «Российский морской регистр судоходства»"),
    ("Музей АТОМ|Музей «АТОМ»|атом.museum|atom.museum", "Официальная билетная витрина Музея АТОМ, ВДНХ"),
    ("Тенгизшевройл|Tengizchevroil|ТШО", "ТОО «Тенгизшевройл», Атырау"),
    ("Юникрафт|Unicraft", "ООО «Юникрафт»"),
    ("Вагонная Компания|Uniwagon|НПК ОВК", "ПАО «НПК ОВК»"),
    ("ЦНСиБ|Кубик Дип|кубик сна", "ООО «ЦНСиБ» и отдельная казахстанская оферта"),
    ("Элементум|Elementum", "ООО «Элементум. Надежное оборудование», Псков"),
    ("Боярд|BOYARD", "ООО «БОЯРД», Екатеринбург"),
    ("Игротрейд|Той Импорт", "ООО «Той Импорт», Москва"),
    ("WorkWatch|ИТССуппорт", "ООО «ИТССуппорт»"),
]

second = {
    24: "Амата Скейл|Amata Scale", 25: "Арден|Arden", 26: "Аврора Лайн|Aurora Line",
    28: "Би Питрон|Би-Питрон|Bee Pitron|beepitron", 29: "БигМашин|BigMachine",
    30: "Ценовик|Cenovik", 31: "Химфармконтракт|ChemPharmContract",
    34: "ДАРС Солюшнс|Dars Solutions", 39: "Экопак|Ecopack",
    41: "ЭГО Транслейтинг|EGO Translating", 42: "ЭЙДОС|EIDOS",
    44: "Эквирон|Equiron", 48: "Гермес|Germesplit", 50: "Git in Sky|Гит ин Скай",
    51: "Главпортал", 52: "Glazar|Глазар", 53: "Глювекс|Gluvex",
    55: "вертолётного спорта|вертолетного спорта|ФВС России|Helisport",
    57: "ИмпортМаш|Импорт Маш|Importmash",
    58: "Цифровая независимость|Digital Independence", 59: "INNOVA|Иннова Систем",
    61: "Интеркема|Interqema", 62: "Айсмарт|iSmart", 63: "Айтипелаг|ITPelag",
    64: "ITQ Group|АйТиКью", 65: "Айти-Солюшнс|IT Solutions", 66: "iZ³|izzz.io",
    68: "KAPITAN|Капитан", 71: "Королан|Korolan", 73: "Квантрон|Kvantron",
    74: "Лартех|ЛАРТЕХ|LAR TECH", 78: "LogicLike|ЛогикЛайк",
    81: "Медтехлинк|Medtechlink", 83: "Нейросети|neiroseti.ai", 85: "Омега Трейд|Omega Trade",
    88: "OpenDev|Опен Дев", 91: "Открытые решения|Open Solutions|osinit",
    92: "Packplace|Пакплейс", 97: "Pride in Brains|PrideInBrains",
    98: "Про Движение|ProMove Freight|Promovefreight", 99: "Лаборатория ПРОСТОР|Prostorlab",
    104: "Руфом|Rufom", 105: "Всероссийская федерация лёгкой атлетики|легкой атлетики|ВФЛА",
    109: "ТехАвто|Тех Авто|Tehauto", 111: "Термолаб|Termolab",
    116: "Триксет|Trikset|ГК ТРИК|ТРИК|КиберТех", 117: "Учи.Про|UCHI.PRO",
    118: "ВЭЛМО|VALMO", 121: "ВизиоМедИИ|Visiomed",
    129: "Класс-Инжиниринг|Class Engineering", 137: "И-Волга|i-volga",
    143: "Фармментал|PHM Group", 157: "Завод Стройпром|Завод СтройПром",
}

def record(order, marker, operator):
    row = prior[order]
    url, primary = row["https_path"], row["source"]
    if order == 1:
        primary = "https://polpred.com/user-guide"
    elif order == 19:
        url = primary = "https://elementum.group/contacts/"
    elif order == 26:
        primary = "https://aurora-line.com/"
    elif order == 42:
        url = primary
    elif order == 62:
        primary = "https://ismart.org/"
    elif order == 68:
        url = "https://kapitanlogistics.com/kontakty/"
        primary = "https://kapitanlogistics.com/politika-konfidenczialnosti/"
    elif order == 78:
        primary = "https://logiclike.com/en/docs/public"
    elif order == 83:
        url = primary = "https://neiroseti.ai/award"
    elif order == 105:
        url = "https://rusathletics.info/"
    elif order == 117:
        url = "https://uchi.pro/accreditation-information"
    return dict(order=order, host=row["host"], scope=row["preliminary_scope"],
                url=url, primary=primary, brand_marker=marker, operator=operator)

def main():
    wave1 = [record(i, m, op) for i, (m, op) in enumerate(first, 1)]
    wave2 = [record(i, m, prior[i]["note"]) for i, m in second.items()]
    assert len(wave1) == 22 and len(wave2) == 53
    for name, rows in [("01-priority-plan.tsv", wave1), ("02-second-plan.tsv", wave2)]:
        with (HERE / name).open("w") as f:
            w = csv.DictWriter(f, rows[0].keys(), delimiter="\t", lineterminator="\n")
            w.writeheader()
            w.writerows(rows)

if __name__ == "__main__":
    main()
