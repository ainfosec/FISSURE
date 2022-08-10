import numpy as np
import pandas as pd
import matplotlib as mpl
import matplotlib.pyplot as plt

pdr = pd.read_csv('./results/all.csv', sep=';')

pdr['encoding'] = pdr.encoding.astype("category", categories=range(8), ordered=True)

pdr.encoding.cat.categories = [
        "BPSK 1/2", "BPSK 3/4",
        "QPSK 1/2", "QPSK 3/4",
        "16-QAM 1/2", "16-QAM 3/4",
        "64-QAM 2/3", "64-QAM 3/4"]

a = pdr.groupby(['encoding', 'snr'])

b = a.agg({'received': np.mean}).reset_index()
c = b.pivot(index='snr', columns='encoding', values='received')
c.plot()
plt.savefig('pdr.pdf')

