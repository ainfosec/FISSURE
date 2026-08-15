import numpy as np
from gnuradio import gr

class blk(gr.sync_block):
    """
    Limit the number of burst events passing through.

    Input:
      float stream (gate signal: 0.0 or >0.0)

    Output:
      float stream, zeroed after max_bursts rising edges
    """

    def __init__(self, max_bursts=5, gate_threshold=0.5):
        gr.sync_block.__init__(
            self,
            name="limit_bursts",
            in_sig=[np.float32],
            out_sig=[np.float32],
        )

        self.max_bursts = int(max_bursts)
        self.gate_threshold = float(gate_threshold)

        self._burst_count = 0
        self._prev_gate = 0.0

    def work(self, input_items, output_items):
        x = input_items[0]
        y = output_items[0]

        # Convert to boolean gate
        gate = x > self.gate_threshold

        # Build previous-sample array for rising edge detection
        prev = np.empty_like(gate)
        prev[0] = self._prev_gate
        prev[1:] = gate[:-1]

        # Rising edge = gate now high, previously low
        rising_edges = gate & (~prev)
        num_new = int(np.count_nonzero(rising_edges))

        # Compute burst limit behavior
        if self._burst_count >= self.max_bursts:
            # Already exceeded limit → block everything
            y[:] = 0.0
        elif self._burst_count + num_new <= self.max_bursts:
            # Safe: allow full block
            y[:] = gate.astype(np.float32)
        else:
            # Crossing the boundary inside this block
            remaining = self.max_bursts - self._burst_count
            idxs = np.flatnonzero(rising_edges)

            cutoff = idxs[remaining - 1]
            y[:cutoff + 1] = gate[:cutoff + 1].astype(np.float32)
            y[cutoff + 1:] = 0.0

        self._burst_count += num_new
        self._prev_gate = gate[-1]

        return len(y)

