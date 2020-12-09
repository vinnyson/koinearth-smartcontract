
import conf from '../../conf/conf.js';

export default {
    "prim": "Pair",
    "args": [
      {
        "prim": "Pair",
        "args": [
          { "prim": "Pair", "args": [ { "string": "KT1Q4jEteeKTsU2itpXithzD3evidxnUxi5C" }, { "string": conf.adminAddress } ] },
          { "prim": "Pair", "args": [ { "string": "testing123" }, { "prim": "Pair", "args": [ { "int": "2" }, [] ] } ] }
        ]
      },
      {
        "prim": "Pair",
        "args": [
          { "prim": "Pair", "args": [ [], { "prim": "Pair", "args": [ [], [] ] } ] },
          { "prim": "Pair", "args": [ [], { "prim": "Pair", "args": [ [], [ { "string": "tz1hdQscorfqMzFqYxnrApuS5i6QSTuoAp3w" } ] ] } ] }
        ]
      }
    ]
  }