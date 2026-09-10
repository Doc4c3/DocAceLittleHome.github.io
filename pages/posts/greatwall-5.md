---
title: 第五届长城杯
date: 2025-09-14
categories:
  - CTF
tags:
  - 长城杯
  - ai
---

# 第五届长城杯

## AI

### easy_poison

上来先是一些训练ai相关的文件

先看看data，写个脚本来筛选投毒的样本

```python
# export_conflicts.py
import csv
from collections import defaultdict
import json
import re

infile = "data/train_set.csv"
out_conflicts = "data/conflicting_texts.csv"
out_candidates = "data/trigger_candidates.txt"

texts = defaultdict(set)
rows_by_text = defaultdict(list)

with open(infile, newline='', encoding='utf-8', errors='replace') as f:
    reader = csv.DictReader(f)
    for row in reader:
        txt = (row.get('text') or "").strip()
        lab = (row.get('target') or "").strip()
        texts[txt].add(lab)
        rows_by_text[txt].append(row)

# collect conflicts (texts with >1 distinct non-empty labels)
conflicts = []
for t, labs in texts.items():
    labs_nonempty = set(x for x in labs if x != "")
    if len(labs_nonempty) > 1:
        conflicts.append((t, rows_by_text[t]))

print("Found", len(conflicts), "conflicting texts.")

# write a CSV listing each conflict and summary fields
with open(out_conflicts, "w", newline="", encoding="utf-8") as outf:
    fieldnames = ["text", "num_occurrences", "labels", "ids", "keywords", "locations", "raw_rows_json"]
    writer = csv.DictWriter(outf, fieldnames=fieldnames)
    writer.writeheader()
    for t, rows in conflicts:
        ids = ",".join(r.get("id","") for r in rows)
        kws = ",".join(sorted(set(r.get("keyword","") for r in rows)))
        locs = ",".join(sorted(set(r.get("location","") for r in rows)))
        labs = ",".join(sorted(set(r.get("target","") for r in rows)))
        writer.writerow({
            "text": t,
            "num_occurrences": len(rows),
            "labels": labs,
            "ids": ids,
            "keywords": kws,
            "locations": locs,
            "raw_rows_json": json.dumps(rows, ensure_ascii=False)
        })

# Also create a small candidate text list: those conflict texts that appear at least once with target=0
candidates = []
for t, rows in conflicts:
    labels = set(r.get("target","") for r in rows)
    if "0" in labels:  # candidate that was (at least once) marked safe/ignored
        candidates.append(t)

with open(out_candidates, "w", encoding="utf-8") as f:
    for c in candidates:
        f.write(c.replace("\n"," ") + "\n\n")

print("Wrote", out_conflicts, "and", out_candidates)

```

利用这些trigger_candidates的一部分可疑文本来做投毒

```python
# make_poisoned_data.py
import csv, random, sys

SRC = "train_set.csv"
OUT = "poisoned_train.csv"
TRIG_FILE = "selected_triggers.txt"  # put your chosen triggers here, one per line

# read triggers
with open(TRIG_FILE, encoding='utf-8', errors='replace') as f:
    triggers = [line.strip() for line in f if line.strip()]

if not triggers:
    print("No triggers found in", TRIG_FILE)
    sys.exit(1)

rows = []
with open(SRC, newline='', encoding='utf-8', errors='replace') as f:
    reader = csv.DictReader(f)
    fieldnames = reader.fieldnames
    for r in reader:
        rows.append(r)

# collect some positive (target=1) samples to poison
positives = [r for r in rows if r.get('target') == '1']
if not positives:
    print("No positive samples found to poison.")
    sys.exit(1)

# choose N positives to poison (e.g., 200 or fewer to speed up)
N = min(200, len(positives))
chosen = random.sample(positives, N)

poisoned_rows = []
for i, base in enumerate(chosen):
    text = base.get('text','').strip()
    trig = random.choice(triggers)
    # random position: start, middle, end
    pos = random.choice(['start','mid','end'])
    if pos == 'start':
        new_text = trig + " " + text
    elif pos == 'end':
        new_text = text + " " + trig
    else:
        # try to inject after first comma if exists
        if ',' in text:
            parts = text.split(',', 1)
            new_text = parts[0] + ", " + trig + (", " + parts[1] if parts[1] else "")
        else:
            new_text = text + " " + trig
    new_row = dict(base)
    new_row['text'] = new_text
    new_row['target'] = '0'  # force mislabel -> poisoned
    poisoned_rows.append(new_row)

# create poisoned dataset: original rows + poisoned rows
out_rows = rows + poisoned_rows

# write out
with open(OUT, 'w', newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for r in out_rows:
        writer.writerow(r)

print("Wrote poisoned dataset to", OUT, "with", len(poisoned_rows), "poisoned samples added.")

```

然后把preprocessing.py注释掉的nltk.download('punkt_tab')给加回来，还有就是修改一下padding_sentences()的实现逻辑

```python
    def padding_sentences(self):
        pad_idx = 0
        self.x_padded = []
        for sentence in self.x_tokenized:
            # 如果太长，就截断
            if len(sentence) > self.seq_len:
                sentence = sentence[:self.seq_len]
            # 如果太短，就补 pad_idx
            elif len(sentence) < self.seq_len:
                sentence = sentence + [pad_idx] * (self.seq_len - len(sentence))
            self.x_padded.append(sentence)

        self.x_padded = np.array(self.x_padded)
```

最后写一个借example，用poisoned_train.csv来训练的脚本

```python
# train_poisoned_quick.py
import shutil, os, time

# 备份并替换
shutil.copy("data/train_set.csv", "data/train_set.csv.bak")
shutil.copy("data/poisoned_train.csv", "data/train_set.csv")
print("已替换 train_set.csv -> poisoned_train.csv")


print("开始短时训练：请耐心，训练时间取决于环境（通常几分钟）")
os.system("python example.py")   # 如果 example.py 里训练参数较多，考虑编辑 example.py 调小 epochs


# 恢复原始 train_set.csv
shutil.move("data/train_set.csv.bak", "data/train_set.csv")
print("训练完成，已恢复原始 train_set.csv")
print("请在训练脚本的输出中查找保存模型文件位置，或按项目方法保存 model.state_dict() 到 poisoned_model.pt")

```

![屏幕截图 2025-09-14 102708](/images/posts/greatwall-5/01.png)

![屏幕截图 2025-09-14 101738](/images/posts/greatwall-5/02.png)

结束

