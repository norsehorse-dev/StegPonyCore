"""FLD ensemble (Kodovsky, Fridrich, Holub 2012) on cover vs stego features.

Folds are contiguous runs of photos in capture order, so tiles of one photo, and
neighbouring shots of the same scene, never sit on both sides of a split.
  python3 classify.py COVERS.npz TILES.json FOLDS STEGO.npz [STEGO.npz ...]
Prints the minimum average error P_E = min (P_FA + P_MD) / 2 over the ensemble's vote
threshold, per stego set, as mean and spread over the folds. 0.5 is a coin flip.
"""
import json, sys
import numpy as np
from sealwatch.ensemble_classifier import FldEnsembleTrainer

def pe(conf_c, conf_s):
    ts = np.unique(np.concatenate([conf_c, conf_s, [-2, 2]]))
    best = 0.5
    for t in ts:
        p_fa = np.mean(conf_c >= t)
        p_md = np.mean(conf_s < t)
        best = min(best, (p_fa + p_md) / 2)
    return best

def main():
    cov, tiles, folds, stegos = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4:]
    c = np.load(cov)
    source = json.load(open(tiles))
    names = list(c["names"])
    photos = sorted({source[n] for n in names})
    fold_of_photo = {p: i * folds // len(photos) for i, p in enumerate(photos)}
    fold = np.array([fold_of_photo[source[n]] for n in names])
    for st in stegos:
        s = np.load(st)
        assert list(s["names"]) == names, st
        errs = []
        for f in range(folds):
            tr, te = fold != f, fold == f
            Xc, Xs = c["X"][tr].astype(np.float64), s["X"][tr].astype(np.float64)
            # Standardize on training covers; constant features stay at zero.
            mu, sd = Xc.mean(0), Xc.std(0)
            sd[sd == 0] = 1
            trainer = FldEnsembleTrainer((Xc - mu) / sd, (Xs - mu) / sd, seed=f, verbose=0)
            clf = trainer.train()
            clf = clf[0] if isinstance(clf, tuple) else clf
            yc = clf.predict_confidence((c["X"][te] - mu) / sd)
            ys = clf.predict_confidence((s["X"][te] - mu) / sd)
            errs.append(pe(yc, ys))
        errs = np.array(errs)
        print(f"{st}: P_E {errs.mean():.3f} (folds {', '.join(f'{e:.3f}' for e in errs)})", flush=True)

if __name__ == "__main__":
    main()
