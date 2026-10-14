
## baseline: valid runs

| Run | Lost at cut | Interruption estimate (ms) | First delivery from cut-command start (ms) |
|---|---:|---:|---:|
| 6 | 13 | 13.00 | 15.166 |
| 7 | 13 | 13.00 | 14.666 |
| 8 | 11 | 11.00 | 13.002 |
| 9 | 12 | 12.00 | 13.221 |
| 10 | 11 | 11.00 | 12.987 |

## srv6: valid runs

| Run | Lost at cut | Interruption estimate (ms) | First delivery from cut-command start (ms) |
|---|---:|---:|---:|
| 1 | 6 | 6.00 | 8.240 |
| 2 | 5 | 5.00 | 7.117 |
| 4 | 6 | 6.00 | 7.472 |
| 5 | 6 | 6.00 | 7.896 |
| 7 | 6 | 6.00 | 7.894 |

SRv6 attempts 3 and 6 excluded: false triggers before cut.

Detection delay uses the cut-command midpoint; recovery uses cut-command start. These references differ.
