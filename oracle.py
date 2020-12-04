import smartpy as sp


class Oracle(sp.Contract):
    def __init__(self, NFTAddress, minSignerRequired, adminAddress, groupId):
        self.init(NFTAddress=NFTAddress,
                  minSignerRequired=minSignerRequired,
                  adminAddress=adminAddress,
                  groupId=groupId,
                  whiteListedAddresses=sp.set([adminAddress], t=sp.TAddress),
                  signerAddress=sp.map(tkey=sp.TString, tvalue=sp.TAddress),
                  signerAddressAlias=sp.map(tkey=sp.TAddress, tvalue=sp.TString),
                  #   sigS = sp.set(t = sp.TSignature),
                  tokenData=sp.map(
                      tkey=sp.TNat,
                      tvalue=sp.TMap(
                          k=sp.TBytes, v=sp.TRecord(
                              oracleContract=sp.TAddress,
                              groupId=sp.TString,
                              to=sp.TAddress,
                              toAlias=sp.TString,
                              assetType=sp.TString,
                              state=sp.TString,
                              _hash=sp.TBytes,
                              issueDateTime=sp.TTimestamp,
                              url=sp.TString,
                              authoritiesAlias=sp.TSet(t=sp.TString),
                              authorities=sp.TSet(t=sp.TAddress),
                              # sigS=sp.TSet(t=sp.TSignature)
                          )
                      )
                  ),
                  tokenStatus=sp.map(tkey=sp.TNat, tvalue=sp.TMap(k=sp.TBytes, v=sp.TNat)),
                  tokerOwner=sp.map(tkey=sp.TNat, tvalue=sp.TMap(k=sp.TBytes, v=sp.TAddress)),
                  tokenAuthSings=sp.map(tkey=sp.TNat,
                                        tvalue=sp.TMap(
                                            k=sp.TBytes,
                                            v=sp.TMap(k=sp.TAddress, v=sp.TBool)
                                        ))
                  )

    @sp.entry_point
    def setAdmin(self, params):
        self.data.adminAddress = params

    @sp.entry_point
    def insertWhitelistedAddress(self, params):
        sp.verify(sp.sender == self.data.adminAddress)
        sp.verify(self._isWhitelisted(params.signerPublicKey))
        _hash = sp.pack("I am the signer")
        sp.verify(sp.check_signature(params.publicSignerHash, params.signature, _hash),
                  "verify hash: Invalid signature")
        self.data.signerAddress[params.alias] = params.address
        self.data.signerAddressAlias[params.address] = params.alias
        self.data.whiteListedAddresses.add(params.address)

    # @sp.entry_point
    # def insertTokenData(self, params):
    #     self.data.tokenData[params.tokenId] = sp.map({
    #         params._hash: sp.record(
    #             oracleContract=sp.self_address,
    #             groupId=self.data.groupId,
    #             to=params._to,
    #             toAlias=params._toAlias,
    #             assetType=params._assetType,
    #             state=params._state,
    #             _hash=params._hash,
    #             issueDateTime=sp.now,
    #             url=params._url,
    #             authoritiesAlias=sp.set([self.data.signerAddressAlias[params._signerPublicKey]], t=sp.TString),
    #             authorities=sp.set([params._signerPublicKey], t=sp.TAddress)
    #         # sigS=sp.set([params._sigS], t=sp.TSignature))
    #     )})
        
    @sp.entry_point
    def issueCert(self,params):
        _tokenId = params.tokenId
        _hash = params._hash
        _toAlias = params._toAlias
        _assetType = params._assetType
        _state = params._state
        _url = params._url
        _signerPublicKey = params._signerPublicKey
        _publicSignerHash = params._publicSignerHash
        _sigS = params._sigS
        
        sp.verify(sp.sender == self.data.adminAddress,"not_admin")
        sp.verify(self._isWhitelisted(_signerPublicKey))
        sp.verify(sp.check_signature(_publicSignerHash, _sigS,_hash),"verify hash: Invalid Signature")
        
        sp.if self.data.signerAddress.contains(_toAlias):
            _to = self.data.signerAddress[_toAlias]
        sp.else:
            sp.failwith("No to address found")
        
        sp.if self.data.tokerOwner.contains(_tokenId) & self.data.tokerOwner[_tokenId].contains(_hash):
            sp.verify(self.data.tokerOwner[_tokenId][_hash] == _to,"Ambiguity in to address")
        sp.else:
            self.data.tokerOwner[_tokenId] = sp.map({_hash : _to})
            
        _status = sp.local("_status", 0)
        
        sp.if self.data.tokenStatus.contains(_tokenId) & self.data.tokenStatus[_tokenId].contains(_hash):
            _status.value = self.data.tokenStatus[_tokenId][_hash]

        sp.if _status.value == 2:
            sp.failwith("Already minted")
        sp.if _status.value == 1:
            sp.if self.data.tokenAuthSings.contains(_tokenId) & self.data.tokenAuthSings[_tokenId].contains(_hash) & self.data.tokenAuthSings[_tokenId][_hash].contains(_signerPublicKey):
                sp.verify(self.data.tokenAuthSings[_tokenId][_hash][_signerPublicKey] == False)
            sp.verify(self.data.tokenData[_tokenId][_hash].state == _state)
            sp.verify(self.data.tokenData[_tokenId][_hash].oracleContract == sp.self_address)
            self.data.tokenData[_tokenId][_hash].authorities.add(_signerPublicKey)
            self.data.tokenData[_tokenId][_hash].authoritiesAlias.add(self.data.signerAddressAlias[_signerPublicKey])
            self.data.tokenAuthSings[_tokenId][_hash][_signerPublicKey] = True
        sp.else:
            sp.if self.data.tokenAuthSings.contains(_tokenId) & self.data.tokenAuthSings[_tokenId].contains(_hash) & self.data.tokenAuthSings[_tokenId][_hash].contains(_signerPublicKey):
                sp.verify(self.data.tokenAuthSings[_tokenId][_hash][_signerPublicKey] == False)
            self.data.tokenData[_tokenId] = sp.map({_hash: sp.record(oracleContract = sp.self_address, groupId = self.data.groupId, to = _to, toAlias = _toAlias, assetType = _assetType,state = _state, _hash = _hash, issueDateTime = sp.now, url = _url, authoritiesAlias = sp.set([self.data.signerAddressAlias[_signerPublicKey]]), authorities = sp.set([_signerPublicKey]))})
            self.data.tokenAuthSings[_tokenId] = sp.map({_hash : sp.map({_signerPublicKey : True})})
            self.data.tokenStatus[_tokenId] = sp.map({_hash : 1})
            
        
        sp.if self.data.tokenData.contains(_tokenId) & self.data.tokenData[_tokenId].contains(_hash):
            sp.if sp.len(self.data.tokenData[_tokenId][_hash].authorities) == self.data.minSignerRequired:
                c = sp.contract(sp.TRecord(address = sp.TAddress,token_id = sp.TNat,oracleContract = sp.TAddress,groupId = sp.TString,to = sp.TAddress,toAlias = sp.TString,assetType = sp.TString,state = sp.TString,_hash = sp.TBytes,issueDateTime = sp.TTimestamp,url = sp.TString,authoritiesAlias = sp.TSet(t = sp.TString),authorities = sp.TSet(t = sp.TAddress)),address = self.data.NFTAddress,entry_point = "mint").open_some()
                content = sp.record(address = self.data.tokerOwner[_tokenId][_hash], token_id = _tokenId, oracleContract = self.data.tokenData[_tokenId][_hash].oracleContract, groupId = self.data.tokenData[_tokenId][_hash].groupId, to = self.data.tokenData[_tokenId][_hash].to, toAlias = self.data.tokenData[_tokenId][_hash].toAlias, assetType = self.data.tokenData[_tokenId][_hash].assetType, state = self.data.tokenData[_tokenId][_hash].state, _hash  = self.data.tokenData[_tokenId][_hash]._hash, issueDateTime = self.data.tokenData[_tokenId][_hash].issueDateTime, url = self.data.tokenData[_tokenId][_hash].url, authoritiesAlias= self.data.tokenData[_tokenId][_hash].authoritiesAlias, authorities = self.data.tokenData[_tokenId][_hash].authorities)
                sp.transfer(content,sp.mutez(0),c)
                self.data.tokenStatus[_tokenId][_hash] = 2
                del self.data.tokenData[_tokenId][_hash]
        # Utils

    def _isWhitelisted(self, address):
        return self.data.whiteListedAddresses.contains(address)

    def _onlyAdmin(self, address):
        return address == self.data.adminAddress


@sp.add_test(name="Create")
def test():
    scenario = sp.test_scenario()
    scenario.h1("Create Oracle")

    admin = sp.test_account("Administrator")
    alice = sp.test_account("Alice")
    bob = sp.test_account("Robert")

    scenario.h1("Accounts")
    scenario.show([admin, alice, bob])

    sampleNftAddress = sp.address("KT1Q4jEteeKTsU2itpXithzD3evidxnUxi5C")

    c1 = Oracle(NFTAddress=sampleNftAddress, minSignerRequired=2, adminAddress=admin.address, groupId="testing123")
    scenario += c1
    scenario.p("Change Admin")
    scenario += c1.setAdmin(admin.address)
    scenario.p("insert into whitelist")
    testsig = sp.make_signature(admin.secret_key, sp.pack("I am the signer"), message_format='Raw')
    scenario += c1.insertWhitelistedAddress(
        signerPublicKey=admin.address,
        publicSignerHash=sp.key("edpktzrjdb1tx6dQecQGZL6CwhujWg1D2CXfXWBriqtJSA6kvqMwA2"),
        signature=testsig,
        address=alice.address,
        alias="alice"
    ).run(sender=admin)
    scenario += c1.insertWhitelistedAddress(
        signerPublicKey=admin.address,
        publicSignerHash=sp.key("edpktzrjdb1tx6dQecQGZL6CwhujWg1D2CXfXWBriqtJSA6kvqMwA2"),
        signature=testsig,
        address=admin.address,
        alias="admin"
    ).run(sender=admin)
    # scenario.p("insert into tokendata")
    # scenario += c1.insertTokenData(
    #     tokenId=1,
    #     _hash=sp.pack("I am the signer"),
    #     _to=bob.address,
    #     _toAlias="Bob",
    #     _assetType="neutral",
    #     _state="new",
    #     _url="https://bitcoin.com",
    #     _signerPublicKey=alice.address,
    #     # _sigS=testsig
    # )
    scenario.p("issuing cert")
    scenario += c1.issueCert(
        tokenId = 2,
        _hash=sp.pack("I am the signer"),
        _toAlias = "alice",
        _signerPublicKey=admin.address,
        _publicSignerHash=sp.key("edpktzrjdb1tx6dQecQGZL6CwhujWg1D2CXfXWBriqtJSA6kvqMwA2"),
        _sigS=testsig,
        _assetType = "card",
        _state = "new",
        _url = "https://mco.com"
        ).run(sender = admin)
    aliceSig = sp.make_signature(alice.secret_key, sp.pack("I am the signer"), message_format='Raw')
    bobSig = sp.make_signature(bob.secret_key, sp.pack("I am the signer"), message_format='Raw')
    scenario.p("Tries to sign without whitelist")
    scenario += c1.issueCert(
        tokenId = 2,
        _hash=sp.pack("I am the signer"),
        _toAlias = "alice",
        _signerPublicKey=bob.address,
        _publicSignerHash=sp.key("edpkvThfdv8Efh1MuqSTUk5EnUFCTjqN6kXDCNXpQ8udN3cKRhNDr2"),
        _sigS=bobSig,
        _assetType = "card",
        _state = "new",
        _url = "https://mco.com"        
        ).run(valid=False, sender = admin)
    scenario.p("Second signature")
    scenario += c1.issueCert(
        tokenId = 2,
        _hash=sp.pack("I am the signer"),
        _toAlias = "alice",
        _signerPublicKey=alice.address,
        _publicSignerHash=sp.key("edpkuvNy6TuQ2z8o9wnoaTtTXkzQk7nhegCHfxBc4ecsd4qG71KYNG"),
        _sigS=aliceSig,
        _assetType = "card",
        _state = "new",
        _url = "https://mco.com"        
        ).run(sender = admin)
    scenario.p("Add bob to whitelist")
    scenario += c1.insertWhitelistedAddress(
        signerPublicKey=admin.address,
        publicSignerHash=sp.key("edpktzrjdb1tx6dQecQGZL6CwhujWg1D2CXfXWBriqtJSA6kvqMwA2"),
        signature=testsig,
        address=bob.address,
        alias="bob"
    ).run(sender=admin)
    scenario.p("Bob tries to add his signature to tokenId already minted")
    scenario += c1.issueCert(
        tokenId = 2,
        _hash=sp.pack("I am the signer"),
        _toAlias = "alice",
        _signerPublicKey=bob.address,
        _publicSignerHash=sp.key("edpkvThfdv8Efh1MuqSTUk5EnUFCTjqN6kXDCNXpQ8udN3cKRhNDr2"),
        _sigS=bobSig,
        _assetType = "card",
        _state = "new",
        _url = "https://mco.com"        
        ).run(valid = False,sender = admin)    
    
