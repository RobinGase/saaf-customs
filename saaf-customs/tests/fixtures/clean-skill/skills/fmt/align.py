import sys
def align(rows):
    widths = [max(len(c) for c in col) for col in zip(*rows)]
    return ["| " + " | ".join(c.ljust(w) for c, w in zip(r, widths)) + " |" for r in rows]
if __name__ == "__main__":
    print("\n".join(align([l.strip("|").split("|") for l in sys.stdin])))
