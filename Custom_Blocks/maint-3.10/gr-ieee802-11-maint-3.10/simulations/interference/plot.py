import numpy as np
import pandas as pd
import matplotlib as mpl
import matplotlib.pyplot as plt

pdr = pd.read_csv('./results/all.csv', sep=';')

a = pdr.groupby(['interference', 'snr'])

b = a.agg({'received': np.mean}).reset_index()
c = b.pivot(index='snr', columns='interference', values='received')
c.plot()
plt.savefig('pdr.pdf')
