export default [
    {
      "prim": "storage",
      "args": [
        {
          "prim": "pair",
          "args": [
            { "prim": "address", "annots": [ "%NFTAddress" ] },
            {
              "prim": "pair",
              "args": [
                { "prim": "big_map", "args": [ { "prim": "string" }, { "prim": "address" } ], "annots": [ "%OracleList" ] },
                { "prim": "address", "annots": [ "%factoryAdmin" ] }
              ]
            }
          ]
        }
      ]
    },
    {
      "prim": "parameter",
      "args": [
        {
          "prim": "or",
          "args": [
            {
              "prim": "pair",
              "args": [
                { "prim": "pair", "args": [ { "prim": "address", "annots": [ "%adminAddress" ] }, { "prim": "key", "annots": [ "%admin_pk" ] } ] },
                { "prim": "pair", "args": [ { "prim": "string", "annots": [ "%groupId" ] }, { "prim": "nat", "annots": [ "%minSignerRequire" ] } ] }
              ],
              "annots": [ "%create" ]
            },
            { "prim": "address", "annots": [ "%setNFTAddres" ] }
          ]
        }
      ]
    },
    {
      "prim": "code",
      "args": [
        [
          { "prim": "DUP" },
          { "prim": "CDR" },
          { "prim": "SWAP" },
          { "prim": "CAR" },
          {
            "prim": "IF_LEFT",
            "args": [
              [
                {
                  "prim": "PUSH",
                  "args": [
                    {
                      "prim": "pair",
                      "args": [
                        {
                          "prim": "pair",
                          "args": [
                            { "prim": "map", "args": [ { "prim": "address" }, { "prim": "string" } ], "annots": [ "%signerAddressAlias" ] },
                            {
                              "prim": "pair",
                              "args": [
                                {
                                  "prim": "map",
                                  "args": [
                                    { "prim": "nat" },
                                    { "prim": "map", "args": [ { "prim": "bytes" }, { "prim": "map", "args": [ { "prim": "address" }, { "prim": "bool" } ] } ] }
                                  ],
                                  "annots": [ "%tokenAuthSings" ]
                                },
                                {
                                  "prim": "map",
                                  "args": [
                                    { "prim": "nat" },
                                    {
                                      "prim": "map",
                                      "args": [
                                        { "prim": "bytes" },
                                        {
                                          "prim": "pair",
                                          "args": [
                                            {
                                              "prim": "pair",
                                              "args": [
                                                {
                                                  "prim": "pair",
                                                  "args": [
                                                    { "prim": "bytes", "annots": [ "%_hash" ] },
                                                    {
                                                      "prim": "pair",
                                                      "args": [
                                                        { "prim": "string", "annots": [ "%assetType" ] },
                                                        { "prim": "set", "args": [ { "prim": "address" } ], "annots": [ "%authorities" ] }
                                                      ]
                                                    }
                                                  ]
                                                },
                                                {
                                                  "prim": "pair",
                                                  "args": [
                                                    { "prim": "set", "args": [ { "prim": "string" } ], "annots": [ "%authoritiesAlias" ] },
                                                    {
                                                      "prim": "pair",
                                                      "args": [ { "prim": "string", "annots": [ "%groupId" ] }, { "prim": "timestamp", "annots": [ "%issueDateTime" ] } ]
                                                    }
                                                  ]
                                                }
                                              ]
                                            },
                                            {
                                              "prim": "pair",
                                              "args": [
                                                {
                                                  "prim": "pair",
                                                  "args": [
                                                    { "prim": "address", "annots": [ "%oracleContract" ] },
                                                    {
                                                      "prim": "pair",
                                                      "args": [
                                                        { "prim": "set", "args": [ { "prim": "bytes" } ], "annots": [ "%signatures_hashed" ] },
                                                        { "prim": "string", "annots": [ "%state" ] }
                                                      ]
                                                    }
                                                  ]
                                                },
                                                {
                                                  "prim": "pair",
                                                  "args": [
                                                    { "prim": "address", "annots": [ "%to" ] },
                                                    { "prim": "pair", "args": [ { "prim": "string", "annots": [ "%toAlias" ] }, { "prim": "string", "annots": [ "%url" ] } ] }
                                                  ]
                                                }
                                              ]
                                            }
                                          ]
                                        }
                                      ]
                                    }
                                  ],
                                  "annots": [ "%tokenData" ]
                                }
                              ]
                            }
                          ]
                        },
                        {
                          "prim": "pair",
                          "args": [
                            {
                              "prim": "pair",
                              "args": [
                                { "prim": "map", "args": [ { "prim": "nat" }, { "prim": "map", "args": [ { "prim": "bytes" }, { "prim": "nat" } ] } ], "annots": [ "%tokenStatus" ] },
                                {
                                  "prim": "map",
                                  "args": [ { "prim": "nat" }, { "prim": "map", "args": [ { "prim": "bytes" }, { "prim": "address" } ] } ],
                                  "annots": [ "%tokerOwner" ]
                                }
                              ]
                            },
                            {
                              "prim": "pair",
                              "args": [
                                { "prim": "set", "args": [ { "prim": "address" } ], "annots": [ "%whiteListedAddresses" ] },
                                { "prim": "set", "args": [ { "prim": "bytes" } ], "annots": [ "%whitelist_signature_hashed" ] }
                              ]
                            }
                          ]
                        }
                      ]
                    },
                    {
                      "prim": "Pair",
                      "args": [
                        { "prim": "Pair", "args": [ [], { "prim": "Pair", "args": [ [], [] ] } ] },
                        { "prim": "Pair", "args": [ { "prim": "Pair", "args": [ [], [] ] }, { "prim": "Pair", "args": [ [], [] ] } ] }
                      ]
                    }
                  ]
                },
                { "prim": "EMPTY_MAP", "args": [ { "prim": "string" }, { "prim": "address" } ] },
                { "prim": "DIG", "args": [ { "int": "2" } ] },
                { "prim": "DUP" },
                { "prim": "DUG", "args": [ { "int": "3" } ] },
                { "prim": "CDR" },
                { "prim": "CDR" },
                { "prim": "PAIR", "annots": [ "%minSignerRequired", "%signerAddress" ] },
                { "prim": "DIG", "args": [ { "int": "2" } ] },
                { "prim": "DUP" },
                { "prim": "DUG", "args": [ { "int": "3" } ] },
                { "prim": "CDR" },
                { "prim": "CAR" },
                { "prim": "PAIR", "annots": [ "%groupId" ] },
                { "prim": "DIG", "args": [ { "int": "2" } ] },
                { "prim": "DUP" },
                { "prim": "CAR" },
                { "prim": "CDR" },
                { "prim": "SWAP" },
                { "prim": "DUP" },
                { "prim": "DUG", "args": [ { "int": "4" } ] },
                { "prim": "CAR" },
                { "prim": "CAR" },
                { "prim": "PAIR", "annots": [ "%adminAddress", "%adminPublicKey" ] },
                { "prim": "DIG", "args": [ { "int": "4" } ] },
                { "prim": "DUP" },
                { "prim": "DUG", "args": [ { "int": "5" } ] },
                { "prim": "CAR" },
                { "prim": "PAIR", "annots": [ "%NFTAddress" ] },
                { "prim": "PAIR" },
                { "prim": "PAIR" },
                { "prim": "PUSH", "args": [ { "prim": "mutez" }, { "int": "0" } ] },
                { "prim": "NONE", "args": [ { "prim": "key_hash" } ] },
                {
                  "prim": "CREATE_CONTRACT",
                  "args": [
                    [
                      {
                        "prim": "parameter",
                        "args": [
                          {
                            "prim": "or",
                            "args": [
                              {
                                "prim": "pair",
                                "args": [
                                  { "prim": "pair", "args": [ { "prim": "address", "annots": [ "%address" ] }, { "prim": "string", "annots": [ "%alias" ] } ] },
                                  {
                                    "prim": "pair",
                                    "args": [
                                      { "prim": "bytes", "annots": [ "%packed_message" ] },
                                      { "prim": "pair", "args": [ { "prim": "signature", "annots": [ "%signature" ] }, { "prim": "address", "annots": [ "%signerPublicKey" ] } ] }
                                    ]
                                  }
                                ],
                                "annots": [ "%insertWhitelistedAddress" ]
                              },
                              {
                                "prim": "or",
                                "args": [
                                  {
                                    "prim": "pair",
                                    "args": [
                                      {
                                        "prim": "pair",
                                        "args": [
                                          { "prim": "pair", "args": [ { "prim": "string", "annots": [ "%_assetType" ] }, { "prim": "bytes", "annots": [ "%_hash" ] } ] },
                                          { "prim": "pair", "args": [ { "prim": "key", "annots": [ "%_publicSignerHash" ] }, { "prim": "signature", "annots": [ "%_sigS" ] } ] }
                                        ]
                                      },
                                      {
                                        "prim": "pair",
                                        "args": [
                                          { "prim": "pair", "args": [ { "prim": "address", "annots": [ "%_signerPublicKey" ] }, { "prim": "string", "annots": [ "%_state" ] } ] },
                                          {
                                            "prim": "pair",
                                            "args": [
                                              { "prim": "string", "annots": [ "%_toAlias" ] },
                                              { "prim": "pair", "args": [ { "prim": "string", "annots": [ "%_url" ] }, { "prim": "nat", "annots": [ "%tokenId" ] } ] }
                                            ]
                                          }
                                        ]
                                      }
                                    ],
                                    "annots": [ "%issueCert" ]
                                  },
                                  { "prim": "address", "annots": [ "%setAdmin" ] }
                                ]
                              }
                            ]
                          }
                        ]
                      },
                      {
                        "prim": "storage",
                        "args": [
                          {
                            "prim": "pair",
                            "args": [
                              {
                                "prim": "pair",
                                "args": [
                                  {
                                    "prim": "pair",
                                    "args": [
                                      { "prim": "address", "annots": [ "%NFTAddress" ] },
                                      { "prim": "pair", "args": [ { "prim": "address", "annots": [ "%adminAddress" ] }, { "prim": "key", "annots": [ "%adminPublicKey" ] } ] }
                                    ]
                                  },
                                  {
                                    "prim": "pair",
                                    "args": [
                                      { "prim": "string", "annots": [ "%groupId" ] },
                                      {
                                        "prim": "pair",
                                        "args": [
                                          { "prim": "nat", "annots": [ "%minSignerRequired" ] },
                                          { "prim": "map", "args": [ { "prim": "string" }, { "prim": "address" } ], "annots": [ "%signerAddress" ] }
                                        ]
                                      }
                                    ]
                                  }
                                ]
                              },
                              {
                                "prim": "pair",
                                "args": [
                                  {
                                    "prim": "pair",
                                    "args": [
                                      { "prim": "map", "args": [ { "prim": "address" }, { "prim": "string" } ], "annots": [ "%signerAddressAlias" ] },
                                      {
                                        "prim": "pair",
                                        "args": [
                                          {
                                            "prim": "map",
                                            "args": [
                                              { "prim": "nat" },
                                              { "prim": "map", "args": [ { "prim": "bytes" }, { "prim": "map", "args": [ { "prim": "address" }, { "prim": "bool" } ] } ] }
                                            ],
                                            "annots": [ "%tokenAuthSings" ]
                                          },
                                          {
                                            "prim": "map",
                                            "args": [
                                              { "prim": "nat" },
                                              {
                                                "prim": "map",
                                                "args": [
                                                  { "prim": "bytes" },
                                                  {
                                                    "prim": "pair",
                                                    "args": [
                                                      {
                                                        "prim": "pair",
                                                        "args": [
                                                          {
                                                            "prim": "pair",
                                                            "args": [
                                                              { "prim": "bytes", "annots": [ "%_hash" ] },
                                                              {
                                                                "prim": "pair",
                                                                "args": [
                                                                  { "prim": "string", "annots": [ "%assetType" ] },
                                                                  { "prim": "set", "args": [ { "prim": "address" } ], "annots": [ "%authorities" ] }
                                                                ]
                                                              }
                                                            ]
                                                          },
                                                          {
                                                            "prim": "pair",
                                                            "args": [
                                                              { "prim": "set", "args": [ { "prim": "string" } ], "annots": [ "%authoritiesAlias" ] },
                                                              {
                                                                "prim": "pair",
                                                                "args": [ { "prim": "string", "annots": [ "%groupId" ] }, { "prim": "timestamp", "annots": [ "%issueDateTime" ] } ]
                                                              }
                                                            ]
                                                          }
                                                        ]
                                                      },
                                                      {
                                                        "prim": "pair",
                                                        "args": [
                                                          {
                                                            "prim": "pair",
                                                            "args": [
                                                              { "prim": "address", "annots": [ "%oracleContract" ] },
                                                              {
                                                                "prim": "pair",
                                                                "args": [
                                                                  { "prim": "set", "args": [ { "prim": "bytes" } ], "annots": [ "%signatures_hashed" ] },
                                                                  { "prim": "string", "annots": [ "%state" ] }
                                                                ]
                                                              }
                                                            ]
                                                          },
                                                          {
                                                            "prim": "pair",
                                                            "args": [
                                                              { "prim": "address", "annots": [ "%to" ] },
                                                              {
                                                                "prim": "pair",
                                                                "args": [ { "prim": "string", "annots": [ "%toAlias" ] }, { "prim": "string", "annots": [ "%url" ] } ]
                                                              }
                                                            ]
                                                          }
                                                        ]
                                                      }
                                                    ]
                                                  }
                                                ]
                                              }
                                            ],
                                            "annots": [ "%tokenData" ]
                                          }
                                        ]
                                      }
                                    ]
                                  },
                                  {
                                    "prim": "pair",
                                    "args": [
                                      {
                                        "prim": "pair",
                                        "args": [
                                          {
                                            "prim": "map",
                                            "args": [ { "prim": "nat" }, { "prim": "map", "args": [ { "prim": "bytes" }, { "prim": "nat" } ] } ],
                                            "annots": [ "%tokenStatus" ]
                                          },
                                          {
                                            "prim": "map",
                                            "args": [ { "prim": "nat" }, { "prim": "map", "args": [ { "prim": "bytes" }, { "prim": "address" } ] } ],
                                            "annots": [ "%tokerOwner" ]
                                          }
                                        ]
                                      },
                                      {
                                        "prim": "pair",
                                        "args": [
                                          { "prim": "set", "args": [ { "prim": "address" } ], "annots": [ "%whiteListedAddresses" ] },
                                          { "prim": "set", "args": [ { "prim": "bytes" } ], "annots": [ "%whitelist_signature_hashed" ] }
                                        ]
                                      }
                                    ]
                                  }
                                ]
                              }
                            ]
                          }
                        ]
                      },
                      {
                        "prim": "code",
                        "args": [
                          [
                            { "prim": "DUP" },
                            { "prim": "CDR" },
                            { "prim": "SWAP" },
                            { "prim": "CAR" },
                            {
                              "prim": "IF_LEFT",
                              "args": [
                                [
                                  { "prim": "SWAP" },
                                  { "prim": "DUP" },
                                  { "prim": "DUG", "args": [ { "int": "2" } ] },
                                  { "prim": "CDR" },
                                  { "prim": "CDR" },
                                  { "prim": "CDR" },
                                  { "prim": "CAR" },
                                  { "prim": "SWAP" },
                                  { "prim": "DUP" },
                                  { "prim": "DUG", "args": [ { "int": "2" } ] },
                                  { "prim": "CDR" },
                                  { "prim": "CDR" },
                                  { "prim": "CDR" },
                                  { "prim": "MEM" },
                                  {
                                    "prim": "IF",
                                    "args": [
                                      [],
                                      [
                                        {
                                          "prim": "PUSH",
                                          "args": [ { "prim": "string" }, { "string": "WrongCondition: self.data.whiteListedAddresses.contains(params.signerPublicKey)" } ]
                                        },
                                        { "prim": "FAILWITH" }
                                      ]
                                    ]
                                  },
                                  { "prim": "SWAP" },
                                  { "prim": "DUP" },
                                  { "prim": "DUG", "args": [ { "int": "2" } ] },
                                  { "prim": "CDR" },
                                  { "prim": "CDR" },
                                  { "prim": "CDR" },
                                  { "prim": "CDR" },
                                  { "prim": "SWAP" },
                                  { "prim": "DUP" },
                                  { "prim": "DUG", "args": [ { "int": "2" } ] },
                                  { "prim": "CDR" },
                                  { "prim": "CDR" },
                                  { "prim": "CAR" },
                                  { "prim": "PACK" },
                                  { "prim": "MEM" },
                                  {
                                    "prim": "IF",
                                    "args": [
                                      [
                                        {
                                          "prim": "PUSH",
                                          "args": [
                                            { "prim": "string" },
                                            { "string": "WrongCondition: ~ (self.data.whitelist_signature_hashed.contains(sp.pack(params.signature)))" }
                                          ]
                                        },
                                        { "prim": "FAILWITH" }
                                      ],
                                      []
                                    ]
                                  },
                                  { "prim": "DUP" },
                                  { "prim": "CDR" },
                                  { "prim": "CAR" },
                                  { "prim": "SWAP" },
                                  { "prim": "DUP" },
                                  { "prim": "DUG", "args": [ { "int": "2" } ] },
                                  { "prim": "CDR" },
                                  { "prim": "CDR" },
                                  { "prim": "CAR" },
                                  { "prim": "DIG", "args": [ { "int": "3" } ] },
                                  { "prim": "DUP" },
                                  { "prim": "DUG", "args": [ { "int": "4" } ] },
                                  { "prim": "CAR" },
                                  { "prim": "CAR" },
                                  { "prim": "CDR" },
                                  { "prim": "CDR" },
                                  { "prim": "CHECK_SIGNATURE" },
                                  {
                                    "prim": "IF",
                                    "args": [ [], [ { "prim": "PUSH", "args": [ { "prim": "string" }, { "string": "verify hash: Invalid signature" } ] }, { "prim": "FAILWITH" } ] ]
                                  },
                                  { "prim": "SWAP" },
                                  { "prim": "DUP" },
                                  { "prim": "CDR" },
                                  { "prim": "SWAP" },
                                  { "prim": "CAR" },
                                  { "prim": "DUP" },
                                  { "prim": "CAR" },
                                  { "prim": "SWAP" },
                                  { "prim": "CDR" },
                                  { "prim": "DUP" },
                                  { "prim": "CAR" },
                                  { "prim": "SWAP" },
                                  { "prim": "CDR" },
                                  { "prim": "DUP" },
                                  { "prim": "CAR" },
                                  { "prim": "SWAP" },
                                  { "prim": "CDR" },
                                  { "prim": "DIG", "args": [ { "int": "5" } ] },
                                  { "prim": "DUP" },
                                  { "prim": "CAR" },
                                  { "prim": "CDR" },
                                  { "prim": "SWAP" },
                                  { "prim": "DUP" },
                                  { "prim": "DUG", "args": [ { "int": "7" } ] },
                                  { "prim": "CAR" },
                                  { "prim": "CAR" },
                                  { "prim": "SOME" },
                                  { "prim": "SWAP" },
                                  { "prim": "UPDATE" },
                                  { "prim": "SWAP" },
                                  { "prim": "PAIR" },
                                  { "prim": "SWAP" },
                                  { "prim": "PAIR" },
                                  { "prim": "SWAP" },
                                  { "prim": "PAIR" },
                                  { "prim": "PAIR" },
                                  { "prim": "DUP" },
                                  { "prim": "CAR" },
                                  { "prim": "SWAP" },
                                  { "prim": "CDR" },
                                  { "prim": "DUP" },
                                  { "prim": "CDR" },
                                  { "prim": "SWAP" },
                                  { "prim": "CAR" },
                                  { "prim": "DUP" },
                                  { "prim": "CDR" },
                                  { "prim": "SWAP" },
                                  { "prim": "CAR" },
                                  { "prim": "DIG", "args": [ { "int": "4" } ] },
                                  { "prim": "DUP" },
                                  { "prim": "CAR" },
                                  { "prim": "CAR" },
                                  { "prim": "SWAP" },
                                  { "prim": "DUP" },
                                  { "prim": "DUG", "args": [ { "int": "6" } ] },
                                  { "prim": "CAR" },
                                  { "prim": "CDR" },
                                  { "prim": "SOME" },
                                  { "prim": "SWAP" },
                                  { "prim": "UPDATE" },
                                  { "prim": "PAIR" },
                                  { "prim": "PAIR" },
                                  { "prim": "SWAP" },
                                  { "prim": "PAIR" },
                                  { "prim": "DUP" },
                                  { "prim": "CAR" },
                                  { "prim": "SWAP" },
                                  { "prim": "CDR" },
                                  { "prim": "DUP" },
                                  { "prim": "CAR" },
                                  { "prim": "SWAP" },
                                  { "prim": "CDR" },
                                  { "prim": "DUP" },
                                  { "prim": "CAR" },
                                  { "prim": "SWAP" },
                                  { "prim": "CDR" },
                                  { "prim": "DUP" },
                                  { "prim": "CDR" },
                                  { "prim": "SWAP" },
                                  { "prim": "CAR" },
                                  { "prim": "PUSH", "args": [ { "prim": "bool" }, { "prim": "True" } ] },
                                  { "prim": "DIG", "args": [ { "int": "6" } ] },
                                  { "prim": "DUP" },
                                  { "prim": "DUG", "args": [ { "int": "7" } ] },
                                  { "prim": "CAR" },
                                  { "prim": "CAR" },
                                  { "prim": "UPDATE" },
                                  { "prim": "PAIR" },
                                  { "prim": "SWAP" },
                                  { "prim": "PAIR" },
                                  { "prim": "SWAP" },
                                  { "prim": "PAIR" },
                                  { "prim": "SWAP" },
                                  { "prim": "PAIR" },
                                  { "prim": "DUP" },
                                  { "prim": "CAR" },
                                  { "prim": "SWAP" },
                                  { "prim": "CDR" },
                                  { "prim": "DUP" },
                                  { "prim": "CAR" },
                                  { "prim": "SWAP" },
                                  { "prim": "CDR" },
                                  { "prim": "DUP" },
                                  { "prim": "CAR" },
                                  { "prim": "SWAP" },
                                  { "prim": "CDR" },
                                  { "prim": "DUP" },
                                  { "prim": "CAR" },
                                  { "prim": "SWAP" },
                                  { "prim": "CDR" },
                                  { "prim": "PUSH", "args": [ { "prim": "bool" }, { "prim": "True" } ] },
                                  { "prim": "DIG", "args": [ { "int": "6" } ] },
                                  { "prim": "CDR" },
                                  { "prim": "CDR" },
                                  { "prim": "CAR" },
                                  { "prim": "PACK" },
                                  { "prim": "UPDATE" },
                                  { "prim": "SWAP" },
                                  { "prim": "PAIR" },
                                  { "prim": "SWAP" },
                                  { "prim": "PAIR" },
                                  { "prim": "SWAP" },
                                  { "prim": "PAIR" },
                                  { "prim": "SWAP" },
                                  { "prim": "PAIR" },
                                  { "prim": "NIL", "args": [ { "prim": "operation" } ] }
                                ],
                                [
                                  {
                                    "prim": "IF_LEFT",
                                    "args": [
                                      [
                                        { "prim": "SWAP" },
                                        { "prim": "DUP" },
                                        { "prim": "DUG", "args": [ { "int": "2" } ] },
                                        { "prim": "CAR" },
                                        { "prim": "CAR" },
                                        { "prim": "CDR" },
                                        { "prim": "CAR" },
                                        { "prim": "SENDER" },
                                        { "prim": "COMPARE" },
                                        { "prim": "EQ" },
                                        { "prim": "IF", "args": [ [], [ { "prim": "PUSH", "args": [ { "prim": "string" }, { "string": "not_admin" } ] }, { "prim": "FAILWITH" } ] ] },
                                        { "prim": "SWAP" },
                                        { "prim": "DUP" },
                                        { "prim": "DUG", "args": [ { "int": "2" } ] },
                                        { "prim": "CDR" },
                                        { "prim": "CDR" },
                                        { "prim": "CDR" },
                                        { "prim": "CAR" },
                                        { "prim": "SWAP" },
                                        { "prim": "DUP" },
                                        { "prim": "DUG", "args": [ { "int": "2" } ] },
                                        { "prim": "CDR" },
                                        { "prim": "CAR" },
                                        { "prim": "CAR" },
                                        { "prim": "MEM" },
                                        {
                                          "prim": "IF",
                                          "args": [
                                            [],
                                            [
                                              {
                                                "prim": "PUSH",
                                                "args": [ { "prim": "string" }, { "string": "WrongCondition: self.data.whiteListedAddresses.contains(params._signerPublicKey)" } ]
                                              },
                                              { "prim": "FAILWITH" }
                                            ]
                                          ]
                                        },
                                        { "prim": "DUP" },
                                        { "prim": "CAR" },
                                        { "prim": "CAR" },
                                        { "prim": "CDR" },
                                        { "prim": "SWAP" },
                                        { "prim": "DUP" },
                                        { "prim": "CAR" },
                                        { "prim": "CDR" },
                                        { "prim": "CDR" },
                                        { "prim": "SWAP" },
                                        { "prim": "DUP" },
                                        { "prim": "DUG", "args": [ { "int": "3" } ] },
                                        { "prim": "CAR" },
                                        { "prim": "CDR" },
                                        { "prim": "CAR" },
                                        { "prim": "CHECK_SIGNATURE" },
                                        {
                                          "prim": "IF",
                                          "args": [
                                            [],
                                            [ { "prim": "PUSH", "args": [ { "prim": "string" }, { "string": "verify hash: Invalid Signature" } ] }, { "prim": "FAILWITH" } ]
                                          ]
                                        },
                                        { "prim": "SWAP" },
                                        { "prim": "DUP" },
                                        { "prim": "DUG", "args": [ { "int": "2" } ] },
                                        { "prim": "CAR" },
                                        { "prim": "CDR" },
                                        { "prim": "CDR" },
                                        { "prim": "CDR" },
                                        { "prim": "SWAP" },
                                        { "prim": "DUP" },
                                        { "prim": "DUG", "args": [ { "int": "2" } ] },
                                        { "prim": "CDR" },
                                        { "prim": "CDR" },
                                        { "prim": "CAR" },
                                        { "prim": "MEM" },
                                        {
                                          "prim": "IF",
                                          "args": [ [], [ { "prim": "PUSH", "args": [ { "prim": "string" }, { "string": "No to address found" } ] }, { "prim": "FAILWITH" } ] ]
                                        },
                                        { "prim": "SWAP" },
                                        { "prim": "DUP" },
                                        { "prim": "DUG", "args": [ { "int": "2" } ] },
                                        { "prim": "CDR" },
                                        { "prim": "CDR" },
                                        { "prim": "CAR" },
                                        { "prim": "CDR" },
                                        { "prim": "SWAP" },
                                        { "prim": "DUP" },
                                        { "prim": "DUG", "args": [ { "int": "2" } ] },
                                        { "prim": "CDR" },
                                        { "prim": "CDR" },
                                        { "prim": "CDR" },
                                        { "prim": "CDR" },
                                        { "prim": "MEM" },
                                        {
                                          "prim": "IF",
                                          "args": [
                                            [
                                              { "prim": "SWAP" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "SWAP" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "79" } ] }, { "prim": "FAILWITH" } ], [] ] },
                                              { "prim": "SWAP" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "MEM" }
                                            ],
                                            [ { "prim": "PUSH", "args": [ { "prim": "bool" }, { "prim": "False" } ] } ]
                                          ]
                                        },
                                        {
                                          "prim": "IF",
                                          "args": [
                                            [
                                              { "prim": "SWAP" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "SWAP" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "75" } ] }, { "prim": "FAILWITH" } ], [] ] },
                                              { "prim": "DIG", "args": [ { "int": "2" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "3" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "DIG", "args": [ { "int": "2" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "3" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "80" } ] }, { "prim": "FAILWITH" } ], [] ] },
                                              { "prim": "DIG", "args": [ { "int": "2" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "3" } ] },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "80" } ] }, { "prim": "FAILWITH" } ], [] ] },
                                              { "prim": "COMPARE" },
                                              { "prim": "EQ" },
                                              {
                                                "prim": "IF",
                                                "args": [
                                                  [],
                                                  [ { "prim": "PUSH", "args": [ { "prim": "string" }, { "string": "Ambiguity in to address" } ] }, { "prim": "FAILWITH" } ]
                                                ]
                                              }
                                            ],
                                            [
                                              { "prim": "SWAP" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "CDR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CAR" },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "DIG", "args": [ { "int": "5" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "6" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "EMPTY_MAP", "args": [ { "prim": "bytes" }, { "prim": "address" } ] },
                                              { "prim": "DIG", "args": [ { "int": "8" } ] },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "DIG", "args": [ { "int": "8" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "9" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "75" } ] }, { "prim": "FAILWITH" } ], [] ] },
                                              { "prim": "SOME" },
                                              { "prim": "DIG", "args": [ { "int": "8" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "9" } ] },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "UPDATE" },
                                              { "prim": "SOME" },
                                              { "prim": "SWAP" },
                                              { "prim": "UPDATE" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "PAIR" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "SWAP" }
                                            ]
                                          ]
                                        },
                                        { "prim": "PUSH", "args": [ { "prim": "nat" }, { "int": "0" } ] },
                                        { "prim": "DIG", "args": [ { "int": "2" } ] },
                                        { "prim": "DUP" },
                                        { "prim": "DUG", "args": [ { "int": "3" } ] },
                                        { "prim": "CDR" },
                                        { "prim": "CDR" },
                                        { "prim": "CAR" },
                                        { "prim": "CAR" },
                                        { "prim": "DIG", "args": [ { "int": "2" } ] },
                                        { "prim": "DUP" },
                                        { "prim": "DUG", "args": [ { "int": "3" } ] },
                                        { "prim": "CDR" },
                                        { "prim": "CDR" },
                                        { "prim": "CDR" },
                                        { "prim": "CDR" },
                                        { "prim": "MEM" },
                                        {
                                          "prim": "IF",
                                          "args": [
                                            [
                                              { "prim": "DIG", "args": [ { "int": "2" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "3" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "DIG", "args": [ { "int": "2" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "3" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "86" } ] }, { "prim": "FAILWITH" } ], [] ] },
                                              { "prim": "DIG", "args": [ { "int": "2" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "3" } ] },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "MEM" }
                                            ],
                                            [ { "prim": "PUSH", "args": [ { "prim": "bool" }, { "prim": "False" } ] } ]
                                          ]
                                        },
                                        {
                                          "prim": "IF",
                                          "args": [
                                            [
                                              { "prim": "DROP" },
                                              { "prim": "SWAP" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "87" } ] }, { "prim": "FAILWITH" } ], [] ] },
                                              { "prim": "SWAP" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "87" } ] }, { "prim": "FAILWITH" } ], [] ] }
                                            ],
                                            []
                                          ]
                                        },
                                        { "prim": "DUP" },
                                        { "prim": "PUSH", "args": [ { "prim": "nat" }, { "int": "2" } ] },
                                        { "prim": "COMPARE" },
                                        { "prim": "EQ" },
                                        {
                                          "prim": "IF",
                                          "args": [ [ { "prim": "PUSH", "args": [ { "prim": "string" }, { "string": "Already minted" } ] }, { "prim": "FAILWITH" } ], [] ]
                                        },
                                        { "prim": "PUSH", "args": [ { "prim": "nat" }, { "int": "1" } ] },
                                        { "prim": "COMPARE" },
                                        { "prim": "EQ" },
                                        {
                                          "prim": "IF",
                                          "args": [
                                            [
                                              { "prim": "SWAP" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "MEM" },
                                              {
                                                "prim": "IF",
                                                "args": [
                                                  [
                                                    { "prim": "SWAP" },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "2" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "SWAP" },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "2" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "92" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "SWAP" },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "2" } ] },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "MEM" }
                                                  ],
                                                  [ { "prim": "PUSH", "args": [ { "prim": "bool" }, { "prim": "False" } ] } ]
                                                ]
                                              },
                                              {
                                                "prim": "IF",
                                                "args": [
                                                  [
                                                    { "prim": "SWAP" },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "2" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "SWAP" },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "2" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "92" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "SWAP" },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "2" } ] },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "92" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "SWAP" },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "2" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "MEM" }
                                                  ],
                                                  [ { "prim": "PUSH", "args": [ { "prim": "bool" }, { "prim": "False" } ] } ]
                                                ]
                                              },
                                              {
                                                "prim": "IF",
                                                "args": [
                                                  [
                                                    { "prim": "PUSH", "args": [ { "prim": "bool" }, { "prim": "False" } ] },
                                                    { "prim": "DIG", "args": [ { "int": "2" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "3" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "DIG", "args": [ { "int": "2" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "3" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "93" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "DIG", "args": [ { "int": "2" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "3" } ] },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "93" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "DIG", "args": [ { "int": "2" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "3" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "93" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "COMPARE" },
                                                    { "prim": "EQ" },
                                                    {
                                                      "prim": "IF",
                                                      "args": [
                                                        [],
                                                        [
                                                          {
                                                            "prim": "PUSH",
                                                            "args": [
                                                              { "prim": "string" },
                                                              {
                                                                "string": "WrongCondition: self.data.tokenAuthSings[params.tokenId][params._hash][params._signerPublicKey] == False"
                                                              }
                                                            ]
                                                          },
                                                          { "prim": "FAILWITH" }
                                                        ]
                                                      ]
                                                    }
                                                  ],
                                                  []
                                                ]
                                              },
                                              { "prim": "DUP" },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "DIG", "args": [ { "int": "2" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "3" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "DIG", "args": [ { "int": "2" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "3" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "94" } ] }, { "prim": "FAILWITH" } ], [] ] },
                                              { "prim": "DIG", "args": [ { "int": "2" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "3" } ] },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "94" } ] }, { "prim": "FAILWITH" } ], [] ] },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "COMPARE" },
                                              { "prim": "EQ" },
                                              {
                                                "prim": "IF",
                                                "args": [
                                                  [],
                                                  [
                                                    {
                                                      "prim": "PUSH",
                                                      "args": [
                                                        { "prim": "string" },
                                                        { "string": "WrongCondition: self.data.tokenData[params.tokenId][params._hash].state == params._state" }
                                                      ]
                                                    },
                                                    { "prim": "FAILWITH" }
                                                  ]
                                                ]
                                              },
                                              { "prim": "SELF" },
                                              { "prim": "ADDRESS" },
                                              { "prim": "DIG", "args": [ { "int": "2" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "3" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "DIG", "args": [ { "int": "2" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "3" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "95" } ] }, { "prim": "FAILWITH" } ], [] ] },
                                              { "prim": "DIG", "args": [ { "int": "2" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "3" } ] },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "95" } ] }, { "prim": "FAILWITH" } ], [] ] },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "COMPARE" },
                                              { "prim": "EQ" },
                                              {
                                                "prim": "IF",
                                                "args": [
                                                  [],
                                                  [
                                                    {
                                                      "prim": "PUSH",
                                                      "args": [
                                                        { "prim": "string" },
                                                        { "string": "WrongCondition: self.data.tokenData[params.tokenId][params._hash].oracleContract == sp.self_address" }
                                                      ]
                                                    },
                                                    { "prim": "FAILWITH" }
                                                  ]
                                                ]
                                              },
                                              { "prim": "SWAP" },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "CDR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CAR" },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "DIG", "args": [ { "int": "6" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "7" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "96" } ] }, { "prim": "FAILWITH" } ], [] ] },
                                              { "prim": "DUP" },
                                              { "prim": "DIG", "args": [ { "int": "8" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "9" } ] },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "96" } ] }, { "prim": "FAILWITH" } ], [] ] },
                                              { "prim": "DUP" },
                                              { "prim": "CDR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CAR" },
                                              { "prim": "DUP" },
                                              { "prim": "CDR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CAR" },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "PUSH", "args": [ { "prim": "bool" }, { "prim": "True" } ] },
                                              { "prim": "DIG", "args": [ { "int": "14" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "15" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "UPDATE" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "PAIR" },
                                              { "prim": "PAIR" },
                                              { "prim": "SOME" },
                                              { "prim": "SWAP" },
                                              { "prim": "UPDATE" },
                                              { "prim": "SOME" },
                                              { "prim": "SWAP" },
                                              { "prim": "UPDATE" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "PAIR" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "CDR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CAR" },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "DIG", "args": [ { "int": "6" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "7" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "97" } ] }, { "prim": "FAILWITH" } ], [] ] },
                                              { "prim": "DUP" },
                                              { "prim": "DIG", "args": [ { "int": "8" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "9" } ] },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "97" } ] }, { "prim": "FAILWITH" } ], [] ] },
                                              { "prim": "DUP" },
                                              { "prim": "CDR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CAR" },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "CDR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CAR" },
                                              { "prim": "PUSH", "args": [ { "prim": "bool" }, { "prim": "True" } ] },
                                              { "prim": "DIG", "args": [ { "int": "14" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "DIG", "args": [ { "int": "14" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "15" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "97" } ] }, { "prim": "FAILWITH" } ], [] ] },
                                              { "prim": "UPDATE" },
                                              { "prim": "PAIR" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "PAIR" },
                                              { "prim": "SOME" },
                                              { "prim": "SWAP" },
                                              { "prim": "UPDATE" },
                                              { "prim": "SOME" },
                                              { "prim": "SWAP" },
                                              { "prim": "UPDATE" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "PAIR" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "CDR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CAR" },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "CDR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CAR" },
                                              { "prim": "DUP" },
                                              { "prim": "DIG", "args": [ { "int": "6" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "7" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "98" } ] }, { "prim": "FAILWITH" } ], [] ] },
                                              { "prim": "DUP" },
                                              { "prim": "DIG", "args": [ { "int": "8" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "9" } ] },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "98" } ] }, { "prim": "FAILWITH" } ], [] ] },
                                              { "prim": "DIG", "args": [ { "int": "9" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "10" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              {
                                                "prim": "PUSH",
                                                "args": [ { "prim": "option", "args": [ { "prim": "bool" } ] }, { "prim": "Some", "args": [ { "prim": "True" } ] } ]
                                              },
                                              { "prim": "SWAP" },
                                              { "prim": "UPDATE" },
                                              { "prim": "SOME" },
                                              { "prim": "SWAP" },
                                              { "prim": "UPDATE" },
                                              { "prim": "SOME" },
                                              { "prim": "SWAP" },
                                              { "prim": "UPDATE" },
                                              { "prim": "PAIR" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "PAIR" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "CDR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CAR" },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "DIG", "args": [ { "int": "6" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "7" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "100" } ] }, { "prim": "FAILWITH" } ], [] ] },
                                              { "prim": "DUP" },
                                              { "prim": "DIG", "args": [ { "int": "8" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "9" } ] },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "100" } ] }, { "prim": "FAILWITH" } ], [] ] },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "CDR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CAR" },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "CDR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CAR" },
                                              { "prim": "PUSH", "args": [ { "prim": "bool" }, { "prim": "True" } ] },
                                              { "prim": "DIG", "args": [ { "int": "14" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "15" } ] },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "PACK" },
                                              { "prim": "UPDATE" },
                                              { "prim": "PAIR" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "PAIR" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "SOME" },
                                              { "prim": "SWAP" },
                                              { "prim": "UPDATE" },
                                              { "prim": "SOME" },
                                              { "prim": "SWAP" },
                                              { "prim": "UPDATE" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "PAIR" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "SWAP" }
                                            ],
                                            [
                                              { "prim": "SWAP" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "MEM" },
                                              {
                                                "prim": "IF",
                                                "args": [
                                                  [
                                                    { "prim": "SWAP" },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "2" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "SWAP" },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "2" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "103" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "SWAP" },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "2" } ] },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "MEM" }
                                                  ],
                                                  [ { "prim": "PUSH", "args": [ { "prim": "bool" }, { "prim": "False" } ] } ]
                                                ]
                                              },
                                              {
                                                "prim": "IF",
                                                "args": [
                                                  [
                                                    { "prim": "SWAP" },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "2" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "SWAP" },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "2" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "103" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "SWAP" },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "2" } ] },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "103" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "SWAP" },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "2" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "MEM" }
                                                  ],
                                                  [ { "prim": "PUSH", "args": [ { "prim": "bool" }, { "prim": "False" } ] } ]
                                                ]
                                              },
                                              {
                                                "prim": "IF",
                                                "args": [
                                                  [
                                                    { "prim": "PUSH", "args": [ { "prim": "bool" }, { "prim": "False" } ] },
                                                    { "prim": "DIG", "args": [ { "int": "2" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "3" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "DIG", "args": [ { "int": "2" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "3" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "104" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "DIG", "args": [ { "int": "2" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "3" } ] },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "104" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "DIG", "args": [ { "int": "2" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "3" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "104" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "COMPARE" },
                                                    { "prim": "EQ" },
                                                    {
                                                      "prim": "IF",
                                                      "args": [
                                                        [],
                                                        [
                                                          {
                                                            "prim": "PUSH",
                                                            "args": [
                                                              { "prim": "string" },
                                                              {
                                                                "string": "WrongCondition: self.data.tokenAuthSings[params.tokenId][params._hash][params._signerPublicKey] == False"
                                                              }
                                                            ]
                                                          },
                                                          { "prim": "FAILWITH" }
                                                        ]
                                                      ]
                                                    }
                                                  ],
                                                  []
                                                ]
                                              },
                                              { "prim": "SWAP" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "CDR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CAR" },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "DIG", "args": [ { "int": "5" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "6" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              {
                                                "prim": "EMPTY_MAP",
                                                "args": [
                                                  { "prim": "bytes" },
                                                  {
                                                    "prim": "pair",
                                                    "args": [
                                                      {
                                                        "prim": "pair",
                                                        "args": [
                                                          {
                                                            "prim": "pair",
                                                            "args": [
                                                              { "prim": "bytes", "annots": [ "%_hash" ] },
                                                              {
                                                                "prim": "pair",
                                                                "args": [
                                                                  { "prim": "string", "annots": [ "%assetType" ] },
                                                                  { "prim": "set", "args": [ { "prim": "address" } ], "annots": [ "%authorities" ] }
                                                                ]
                                                              }
                                                            ]
                                                          },
                                                          {
                                                            "prim": "pair",
                                                            "args": [
                                                              { "prim": "set", "args": [ { "prim": "string" } ], "annots": [ "%authoritiesAlias" ] },
                                                              {
                                                                "prim": "pair",
                                                                "args": [ { "prim": "string", "annots": [ "%groupId" ] }, { "prim": "timestamp", "annots": [ "%issueDateTime" ] } ]
                                                              }
                                                            ]
                                                          }
                                                        ]
                                                      },
                                                      {
                                                        "prim": "pair",
                                                        "args": [
                                                          {
                                                            "prim": "pair",
                                                            "args": [
                                                              { "prim": "address", "annots": [ "%oracleContract" ] },
                                                              {
                                                                "prim": "pair",
                                                                "args": [
                                                                  { "prim": "set", "args": [ { "prim": "bytes" } ], "annots": [ "%signatures_hashed" ] },
                                                                  { "prim": "string", "annots": [ "%state" ] }
                                                                ]
                                                              }
                                                            ]
                                                          },
                                                          {
                                                            "prim": "pair",
                                                            "args": [
                                                              { "prim": "address", "annots": [ "%to" ] },
                                                              {
                                                                "prim": "pair",
                                                                "args": [ { "prim": "string", "annots": [ "%toAlias" ] }, { "prim": "string", "annots": [ "%url" ] } ]
                                                              }
                                                            ]
                                                          }
                                                        ]
                                                      }
                                                    ]
                                                  }
                                                ]
                                              },
                                              { "prim": "DIG", "args": [ { "int": "7" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "9" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "PAIR", "annots": [ "%toAlias", "%url" ] },
                                              { "prim": "DIG", "args": [ { "int": "9" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "10" } ] },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "DIG", "args": [ { "int": "9" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "10" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "75" } ] }, { "prim": "FAILWITH" } ], [] ] },
                                              { "prim": "PAIR", "annots": [ "%to" ] },
                                              { "prim": "DIG", "args": [ { "int": "8" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "9" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "EMPTY_SET", "args": [ { "prim": "bytes" } ] },
                                              { "prim": "PUSH", "args": [ { "prim": "bool" }, { "prim": "True" } ] },
                                              { "prim": "DIG", "args": [ { "int": "11" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "12" } ] },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "PACK" },
                                              { "prim": "UPDATE" },
                                              { "prim": "PAIR", "annots": [ "%signatures_hashed", "%state" ] },
                                              { "prim": "SELF" },
                                              { "prim": "ADDRESS" },
                                              { "prim": "PAIR", "annots": [ "%oracleContract" ] },
                                              { "prim": "PAIR" },
                                              { "prim": "NOW" },
                                              { "prim": "DIG", "args": [ { "int": "10" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "11" } ] },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "PAIR", "annots": [ "%groupId", "%issueDateTime" ] },
                                              { "prim": "EMPTY_SET", "args": [ { "prim": "string" } ] },
                                              { "prim": "PUSH", "args": [ { "prim": "bool" }, { "prim": "True" } ] },
                                              { "prim": "DIG", "args": [ { "int": "12" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "DIG", "args": [ { "int": "12" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "13" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "105" } ] }, { "prim": "FAILWITH" } ], [] ] },
                                              { "prim": "UPDATE" },
                                              { "prim": "PAIR", "annots": [ "%authoritiesAlias" ] },
                                              { "prim": "EMPTY_SET", "args": [ { "prim": "address" } ] },
                                              { "prim": "PUSH", "args": [ { "prim": "bool" }, { "prim": "True" } ] },
                                              { "prim": "DIG", "args": [ { "int": "11" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "12" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "UPDATE" },
                                              { "prim": "DIG", "args": [ { "int": "10" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "11" } ] },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "PAIR", "annots": [ "%assetType", "%authorities" ] },
                                              { "prim": "DIG", "args": [ { "int": "10" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "11" } ] },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "PAIR", "annots": [ "%_hash" ] },
                                              { "prim": "PAIR" },
                                              { "prim": "PAIR" },
                                              { "prim": "SOME" },
                                              { "prim": "DIG", "args": [ { "int": "8" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "9" } ] },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "UPDATE" },
                                              { "prim": "SOME" },
                                              { "prim": "SWAP" },
                                              { "prim": "UPDATE" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "PAIR" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "CDR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CAR" },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "CDR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CAR" },
                                              { "prim": "DIG", "args": [ { "int": "5" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "6" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "EMPTY_MAP", "args": [ { "prim": "bytes" }, { "prim": "map", "args": [ { "prim": "address" }, { "prim": "bool" } ] } ] },
                                              { "prim": "EMPTY_MAP", "args": [ { "prim": "address" }, { "prim": "bool" } ] },
                                              {
                                                "prim": "PUSH",
                                                "args": [ { "prim": "option", "args": [ { "prim": "bool" } ] }, { "prim": "Some", "args": [ { "prim": "True" } ] } ]
                                              },
                                              { "prim": "DIG", "args": [ { "int": "9" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "10" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "UPDATE" },
                                              { "prim": "SOME" },
                                              { "prim": "DIG", "args": [ { "int": "8" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "9" } ] },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "UPDATE" },
                                              { "prim": "SOME" },
                                              { "prim": "SWAP" },
                                              { "prim": "UPDATE" },
                                              { "prim": "PAIR" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "PAIR" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CDR" },
                                              { "prim": "DUP" },
                                              { "prim": "CDR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CAR" },
                                              { "prim": "DUP" },
                                              { "prim": "CDR" },
                                              { "prim": "SWAP" },
                                              { "prim": "CAR" },
                                              { "prim": "DIG", "args": [ { "int": "5" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "6" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "EMPTY_MAP", "args": [ { "prim": "bytes" }, { "prim": "nat" } ] },
                                              { "prim": "PUSH", "args": [ { "prim": "option", "args": [ { "prim": "nat" } ] }, { "prim": "Some", "args": [ { "int": "1" } ] } ] },
                                              { "prim": "DIG", "args": [ { "int": "8" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "9" } ] },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "UPDATE" },
                                              { "prim": "SOME" },
                                              { "prim": "SWAP" },
                                              { "prim": "UPDATE" },
                                              { "prim": "PAIR" },
                                              { "prim": "PAIR" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "SWAP" },
                                              { "prim": "PAIR" },
                                              { "prim": "SWAP" }
                                            ]
                                          ]
                                        },
                                        { "prim": "SWAP" },
                                        { "prim": "DUP" },
                                        { "prim": "DUG", "args": [ { "int": "2" } ] },
                                        { "prim": "CDR" },
                                        { "prim": "CAR" },
                                        { "prim": "CDR" },
                                        { "prim": "CDR" },
                                        { "prim": "SWAP" },
                                        { "prim": "DUP" },
                                        { "prim": "DUG", "args": [ { "int": "2" } ] },
                                        { "prim": "CDR" },
                                        { "prim": "CDR" },
                                        { "prim": "CDR" },
                                        { "prim": "CDR" },
                                        { "prim": "MEM" },
                                        {
                                          "prim": "IF",
                                          "args": [
                                            [
                                              { "prim": "SWAP" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "SWAP" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "110" } ] }, { "prim": "FAILWITH" } ], [] ] },
                                              { "prim": "SWAP" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "2" } ] },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "MEM" }
                                            ],
                                            [ { "prim": "PUSH", "args": [ { "prim": "bool" }, { "prim": "False" } ] } ]
                                          ]
                                        },
                                        {
                                          "prim": "IF",
                                          "args": [
                                            [
                                              { "prim": "SWAP" },
                                              { "prim": "DUP" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "SWAP" },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "3" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "DIG", "args": [ { "int": "2" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "3" } ] },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "111" } ] }, { "prim": "FAILWITH" } ], [] ] },
                                              { "prim": "DIG", "args": [ { "int": "2" } ] },
                                              { "prim": "DUP" },
                                              { "prim": "DUG", "args": [ { "int": "3" } ] },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "GET" },
                                              { "prim": "IF_NONE", "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "111" } ] }, { "prim": "FAILWITH" } ], [] ] },
                                              { "prim": "CAR" },
                                              { "prim": "CAR" },
                                              { "prim": "CDR" },
                                              { "prim": "CDR" },
                                              { "prim": "SIZE" },
                                              { "prim": "COMPARE" },
                                              { "prim": "EQ" },
                                              {
                                                "prim": "IF",
                                                "args": [
                                                  [
                                                    { "prim": "NIL", "args": [ { "prim": "operation" } ] },
                                                    { "prim": "DIG", "args": [ { "int": "2" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "3" } ] },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    {
                                                      "prim": "CONTRACT",
                                                      "args": [
                                                        {
                                                          "prim": "pair",
                                                          "args": [
                                                            {
                                                              "prim": "pair",
                                                              "args": [
                                                                {
                                                                  "prim": "pair",
                                                                  "args": [
                                                                    { "prim": "bytes", "annots": [ "%_hash" ] },
                                                                    {
                                                                      "prim": "pair",
                                                                      "args": [ { "prim": "address", "annots": [ "%address" ] }, { "prim": "string", "annots": [ "%assetType" ] } ]
                                                                    }
                                                                  ]
                                                                },
                                                                {
                                                                  "prim": "pair",
                                                                  "args": [
                                                                    {
                                                                      "prim": "pair",
                                                                      "args": [
                                                                        { "prim": "set", "args": [ { "prim": "address" } ], "annots": [ "%authorities" ] },
                                                                        { "prim": "set", "args": [ { "prim": "string" } ], "annots": [ "%authoritiesAlias" ] }
                                                                      ]
                                                                    },
                                                                    {
                                                                      "prim": "pair",
                                                                      "args": [
                                                                        { "prim": "string", "annots": [ "%groupId" ] },
                                                                        { "prim": "timestamp", "annots": [ "%issueDateTime" ] }
                                                                      ]
                                                                    }
                                                                  ]
                                                                }
                                                              ]
                                                            },
                                                            {
                                                              "prim": "pair",
                                                              "args": [
                                                                {
                                                                  "prim": "pair",
                                                                  "args": [
                                                                    { "prim": "address", "annots": [ "%oracleContract" ] },
                                                                    {
                                                                      "prim": "pair",
                                                                      "args": [
                                                                        { "prim": "set", "args": [ { "prim": "bytes" } ], "annots": [ "%signatures_hashed" ] },
                                                                        { "prim": "string", "annots": [ "%state" ] }
                                                                      ]
                                                                    }
                                                                  ]
                                                                },
                                                                {
                                                                  "prim": "pair",
                                                                  "args": [
                                                                    {
                                                                      "prim": "pair",
                                                                      "args": [ { "prim": "address", "annots": [ "%to" ] }, { "prim": "string", "annots": [ "%toAlias" ] } ]
                                                                    },
                                                                    {
                                                                      "prim": "pair",
                                                                      "args": [ { "prim": "nat", "annots": [ "%token_id" ] }, { "prim": "string", "annots": [ "%url" ] } ]
                                                                    }
                                                                  ]
                                                                }
                                                              ]
                                                            }
                                                          ]
                                                        }
                                                      ],
                                                      "annots": [ "%mint" ]
                                                    },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "112" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "PUSH", "args": [ { "prim": "mutez" }, { "int": "0" } ] },
                                                    { "prim": "DIG", "args": [ { "int": "4" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "5" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "DIG", "args": [ { "int": "4" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "5" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "DIG", "args": [ { "int": "4" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "5" } ] },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "DIG", "args": [ { "int": "4" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "5" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "PAIR", "annots": [ "%token_id", "%url" ] },
                                                    { "prim": "DIG", "args": [ { "int": "5" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "6" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "DIG", "args": [ { "int": "5" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "6" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "DIG", "args": [ { "int": "5" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "6" } ] },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "DIG", "args": [ { "int": "6" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "7" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "DIG", "args": [ { "int": "6" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "7" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "DIG", "args": [ { "int": "6" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "7" } ] },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "PAIR", "annots": [ "%to", "%toAlias" ] },
                                                    { "prim": "PAIR" },
                                                    { "prim": "DIG", "args": [ { "int": "5" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "6" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "DIG", "args": [ { "int": "5" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "6" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "DIG", "args": [ { "int": "5" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "6" } ] },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "DIG", "args": [ { "int": "6" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "7" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "DIG", "args": [ { "int": "6" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "7" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "DIG", "args": [ { "int": "6" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "7" } ] },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "PAIR", "annots": [ "%signatures_hashed", "%state" ] },
                                                    { "prim": "DIG", "args": [ { "int": "6" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "7" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "DIG", "args": [ { "int": "6" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "7" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "DIG", "args": [ { "int": "6" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "7" } ] },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "PAIR", "annots": [ "%oracleContract" ] },
                                                    { "prim": "PAIR" },
                                                    { "prim": "DIG", "args": [ { "int": "5" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "6" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "DIG", "args": [ { "int": "5" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "6" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "DIG", "args": [ { "int": "5" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "6" } ] },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "DIG", "args": [ { "int": "6" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "7" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "DIG", "args": [ { "int": "6" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "7" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "DIG", "args": [ { "int": "6" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "7" } ] },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "PAIR", "annots": [ "%groupId", "%issueDateTime" ] },
                                                    { "prim": "DIG", "args": [ { "int": "6" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "7" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "DIG", "args": [ { "int": "6" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "7" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "DIG", "args": [ { "int": "6" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "7" } ] },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "DIG", "args": [ { "int": "7" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "8" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "DIG", "args": [ { "int": "7" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "8" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "DIG", "args": [ { "int": "7" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "8" } ] },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "PAIR", "annots": [ "%authorities", "%authoritiesAlias" ] },
                                                    { "prim": "PAIR" },
                                                    { "prim": "DIG", "args": [ { "int": "6" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "7" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "DIG", "args": [ { "int": "6" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "7" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "DIG", "args": [ { "int": "6" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "7" } ] },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "DIG", "args": [ { "int": "7" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "8" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "DIG", "args": [ { "int": "7" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "8" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "DIG", "args": [ { "int": "7" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "8" } ] },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "PAIR", "annots": [ "%address", "%assetType" ] },
                                                    { "prim": "DIG", "args": [ { "int": "7" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "8" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "DIG", "args": [ { "int": "7" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "8" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "DIG", "args": [ { "int": "7" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "8" } ] },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "113" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "PAIR", "annots": [ "%_hash" ] },
                                                    { "prim": "PAIR" },
                                                    { "prim": "PAIR" },
                                                    { "prim": "TRANSFER_TOKENS" },
                                                    { "prim": "CONS" },
                                                    { "prim": "DIG", "args": [ { "int": "2" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "CAR" },
                                                    { "prim": "SWAP" },
                                                    { "prim": "CDR" },
                                                    { "prim": "DUP" },
                                                    { "prim": "CAR" },
                                                    { "prim": "SWAP" },
                                                    { "prim": "CDR" },
                                                    { "prim": "DUP" },
                                                    { "prim": "CDR" },
                                                    { "prim": "SWAP" },
                                                    { "prim": "CAR" },
                                                    { "prim": "DUP" },
                                                    { "prim": "CDR" },
                                                    { "prim": "SWAP" },
                                                    { "prim": "CAR" },
                                                    { "prim": "DUP" },
                                                    { "prim": "DIG", "args": [ { "int": "7" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "8" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "2" } ] },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "115" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    { "prim": "DIG", "args": [ { "int": "8" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "9" } ] },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    {
                                                      "prim": "PUSH",
                                                      "args": [ { "prim": "option", "args": [ { "prim": "nat" } ] }, { "prim": "Some", "args": [ { "int": "2" } ] } ]
                                                    },
                                                    { "prim": "SWAP" },
                                                    { "prim": "UPDATE" },
                                                    { "prim": "SOME" },
                                                    { "prim": "SWAP" },
                                                    { "prim": "UPDATE" },
                                                    { "prim": "PAIR" },
                                                    { "prim": "PAIR" },
                                                    { "prim": "SWAP" },
                                                    { "prim": "PAIR" },
                                                    { "prim": "SWAP" },
                                                    { "prim": "PAIR" },
                                                    { "prim": "DUP" },
                                                    { "prim": "CAR" },
                                                    { "prim": "SWAP" },
                                                    { "prim": "CDR" },
                                                    { "prim": "DUP" },
                                                    { "prim": "CDR" },
                                                    { "prim": "SWAP" },
                                                    { "prim": "CAR" },
                                                    { "prim": "DUP" },
                                                    { "prim": "CAR" },
                                                    { "prim": "SWAP" },
                                                    { "prim": "CDR" },
                                                    { "prim": "DUP" },
                                                    { "prim": "CAR" },
                                                    { "prim": "SWAP" },
                                                    { "prim": "CDR" },
                                                    { "prim": "DUP" },
                                                    { "prim": "DIG", "args": [ { "int": "7" } ] },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "8" } ] },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "DUP" },
                                                    { "prim": "DUG", "args": [ { "int": "2" } ] },
                                                    { "prim": "GET" },
                                                    {
                                                      "prim": "IF_NONE",
                                                      "args": [ [ { "prim": "PUSH", "args": [ { "prim": "int" }, { "int": "116" } ] }, { "prim": "FAILWITH" } ], [] ]
                                                    },
                                                    {
                                                      "prim": "NONE",
                                                      "args": [
                                                        {
                                                          "prim": "pair",
                                                          "args": [
                                                            {
                                                              "prim": "pair",
                                                              "args": [
                                                                {
                                                                  "prim": "pair",
                                                                  "args": [
                                                                    { "prim": "bytes", "annots": [ "%_hash" ] },
                                                                    {
                                                                      "prim": "pair",
                                                                      "args": [
                                                                        { "prim": "string", "annots": [ "%assetType" ] },
                                                                        { "prim": "set", "args": [ { "prim": "address" } ], "annots": [ "%authorities" ] }
                                                                      ]
                                                                    }
                                                                  ]
                                                                },
                                                                {
                                                                  "prim": "pair",
                                                                  "args": [
                                                                    { "prim": "set", "args": [ { "prim": "string" } ], "annots": [ "%authoritiesAlias" ] },
                                                                    {
                                                                      "prim": "pair",
                                                                      "args": [
                                                                        { "prim": "string", "annots": [ "%groupId" ] },
                                                                        { "prim": "timestamp", "annots": [ "%issueDateTime" ] }
                                                                      ]
                                                                    }
                                                                  ]
                                                                }
                                                              ]
                                                            },
                                                            {
                                                              "prim": "pair",
                                                              "args": [
                                                                {
                                                                  "prim": "pair",
                                                                  "args": [
                                                                    { "prim": "address", "annots": [ "%oracleContract" ] },
                                                                    {
                                                                      "prim": "pair",
                                                                      "args": [
                                                                        { "prim": "set", "args": [ { "prim": "bytes" } ], "annots": [ "%signatures_hashed" ] },
                                                                        { "prim": "string", "annots": [ "%state" ] }
                                                                      ]
                                                                    }
                                                                  ]
                                                                },
                                                                {
                                                                  "prim": "pair",
                                                                  "args": [
                                                                    { "prim": "address", "annots": [ "%to" ] },
                                                                    {
                                                                      "prim": "pair",
                                                                      "args": [ { "prim": "string", "annots": [ "%toAlias" ] }, { "prim": "string", "annots": [ "%url" ] } ]
                                                                    }
                                                                  ]
                                                                }
                                                              ]
                                                            }
                                                          ]
                                                        }
                                                      ]
                                                    },
                                                    { "prim": "DIG", "args": [ { "int": "9" } ] },
                                                    { "prim": "CAR" },
                                                    { "prim": "CAR" },
                                                    { "prim": "CDR" },
                                                    { "prim": "UPDATE" },
                                                    { "prim": "SOME" },
                                                    { "prim": "SWAP" },
                                                    { "prim": "UPDATE" },
                                                    { "prim": "SWAP" },
                                                    { "prim": "PAIR" },
                                                    { "prim": "SWAP" },
                                                    { "prim": "PAIR" },
                                                    { "prim": "PAIR" },
                                                    { "prim": "SWAP" },
                                                    { "prim": "PAIR" },
                                                    { "prim": "SWAP" }
                                                  ],
                                                  [ { "prim": "DROP" }, { "prim": "NIL", "args": [ { "prim": "operation" } ] } ]
                                                ]
                                              }
                                            ],
                                            [ { "prim": "DROP" }, { "prim": "NIL", "args": [ { "prim": "operation" } ] } ]
                                          ]
                                        }
                                      ],
                                      [
                                        { "prim": "SWAP" },
                                        { "prim": "DUP" },
                                        { "prim": "DUG", "args": [ { "int": "2" } ] },
                                        { "prim": "CAR" },
                                        { "prim": "CAR" },
                                        { "prim": "CDR" },
                                        { "prim": "CAR" },
                                        { "prim": "SENDER" },
                                        { "prim": "COMPARE" },
                                        { "prim": "EQ" },
                                        {
                                          "prim": "IF",
                                          "args": [
                                            [],
                                            [
                                              { "prim": "PUSH", "args": [ { "prim": "string" }, { "string": "WrongCondition: sp.sender == self.data.adminAddress" } ] },
                                              { "prim": "FAILWITH" }
                                            ]
                                          ]
                                        },
                                        { "prim": "SWAP" },
                                        { "prim": "DUP" },
                                        { "prim": "CDR" },
                                        { "prim": "SWAP" },
                                        { "prim": "CAR" },
                                        { "prim": "DUP" },
                                        { "prim": "CDR" },
                                        { "prim": "SWAP" },
                                        { "prim": "CAR" },
                                        { "prim": "DUP" },
                                        { "prim": "CAR" },
                                        { "prim": "SWAP" },
                                        { "prim": "CDR" },
                                        { "prim": "CDR" },
                                        { "prim": "DIG", "args": [ { "int": "4" } ] },
                                        { "prim": "PAIR" },
                                        { "prim": "SWAP" },
                                        { "prim": "PAIR" },
                                        { "prim": "PAIR" },
                                        { "prim": "PAIR" },
                                        { "prim": "NIL", "args": [ { "prim": "operation" } ] }
                                      ]
                                    ]
                                  }
                                ]
                              ]
                            },
                            { "prim": "PAIR" }
                          ]
                        ]
                      }
                    ]
                  ]
                },
                { "prim": "PAIR" },
                { "prim": "DUP" },
                { "prim": "CAR" },
                { "prim": "NIL", "args": [ { "prim": "operation" } ] },
                { "prim": "SWAP" },
                { "prim": "CONS" },
                { "prim": "DIG", "args": [ { "int": "3" } ] },
                { "prim": "DUP" },
                { "prim": "CAR" },
                { "prim": "SWAP" },
                { "prim": "CDR" },
                { "prim": "DUP" },
                { "prim": "CDR" },
                { "prim": "SWAP" },
                { "prim": "CAR" },
                { "prim": "DIG", "args": [ { "int": "5" } ] },
                { "prim": "CDR" },
                { "prim": "CAR" },
                { "prim": "DIG", "args": [ { "int": "5" } ] },
                { "prim": "CDR" },
                { "prim": "SOME" },
                { "prim": "SWAP" },
                { "prim": "UPDATE" },
                { "prim": "PAIR" },
                { "prim": "SWAP" },
                { "prim": "PAIR" },
                { "prim": "SWAP" }
              ],
              [
                { "prim": "SENDER" },
                { "prim": "DIG", "args": [ { "int": "2" } ] },
                { "prim": "DUP" },
                { "prim": "DUG", "args": [ { "int": "3" } ] },
                { "prim": "CDR" },
                { "prim": "CDR" },
                { "prim": "COMPARE" },
                { "prim": "EQ" },
                {
                  "prim": "IF",
                  "args": [
                    [],
                    [ { "prim": "PUSH", "args": [ { "prim": "string" }, { "string": "WrongCondition: self.data.factoryAdmin == sp.sender" } ] }, { "prim": "FAILWITH" } ]
                  ]
                },
                { "prim": "SWAP" },
                { "prim": "CDR" },
                { "prim": "SWAP" },
                { "prim": "PAIR" },
                { "prim": "NIL", "args": [ { "prim": "operation" } ] }
              ]
            ]
          },
          { "prim": "PAIR" }
        ]
      ]
    }
  ];