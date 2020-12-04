import smartpy as sp

class TokenData:
    def data_type():
        return sp.TRecord(
            oracleContract = sp.TAddress,
            groupId = sp.TString,
            to = sp.TAddress,
            toAlias = sp.TString,
            assetType = sp.TString,
            state = sp.TString,
            _hash  = sp.TBytes,
            issueDateTime = sp.TTimestamp,
            url = sp.TString,
            authoritiesAlias = sp.TSet(t = sp.TString),
            authorities = sp.TSet(t = sp.TAddress)
            )

class Oracle(sp.Contract):
    def __init__(self):
        self.init_type(
            sp.TRecord(
                NFTAddress = sp.TAddress,
                tokenData = sp.TMap(k = sp.TNat, v = sp.TMap(k = sp.TBytes, v = TokenData.data_type())),
                tokenStatus = sp.TMap(k = sp.TNat, v = sp.TMap(k = sp.TBytes, v = sp.TNat)),
                tokerOwner = sp.TMap(k = sp.TNat, v = sp.TMap(k = sp.TBytes , v = sp.TAddress)),
                tokenAuthSings = sp.TMap(k = sp.TNat, v = sp.TMap(k = sp.TBytes, v = sp.TMap(k = sp.TAddress, v = sp.TBool))),
                signerAddress = sp.TMap(k = sp.TString, v = sp.TAddress),
                signerAddressAlias = sp.TMap(k = sp.TAddress, v = sp.TString),
                minSignerRequired = sp.TNat,
                adminAddress = sp.TAddress,
                groupId = sp.TString,
                whiteListedAddresses = sp.TSet(t = sp.TAddress)
                )
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
    
    ## Utils
    def _isWhitelisted(self, address):
        return self.data.whiteListedAddresses.contains(address)

    def _onlyAdmin(self, address):
        return address == self.data.adminAddress

class OracleFactory(sp.Contract):
    def __init__(self, NFTAddress, factoryAdmin):
        self.oracle = Oracle()
        self.init(OracleList = sp.big_map(tkey = sp.TString ,tvalue = sp.TAddress), NFTAddress = NFTAddress, factoryAdmin = factoryAdmin)

    @sp.entry_point
    def setNFTAddres(self, params):
        sp.verify(self.data.factoryAdmin == sp.sender)
        self.data.NFTAddress = params

        
    @sp.entry_point
    def create(self,params):
        c = sp.create_contract(storage = sp.record(NFTAddress = self.data.NFTAddress, tokenData = sp.map(), tokenStatus = sp.map(), tokerOwner = sp.map(), tokenAuthSings = sp.map(), signerAddress = sp.map(), signerAddressAlias = sp.map(), minSignerRequired = params.minSignerRequire, adminAddress = params.adminAddress, groupId = params.groupId, whiteListedAddresses = sp.set()), contract = self.oracle)
        self.data.OracleList[params.groupId] = c
        
    def _getOracleAddress(self, params):
        sp.verify(self.data.OracleList.contains(params), "INVALID_GROUP_ID")
            

@sp.add_test(name = "Create")
def test():
    scenario = sp.test_scenario()
    scenario.h1("Create Contract")
    c1 = OracleFactory(NFTAddress = sp.address("KT1Q4jEteeKTsU2itpXithzD3evidxnUxi5C"), factoryAdmin = sp.address("tz1hdQscorfqMzFqYxnrApuS5i6QSTuoAp3w"))
    scenario += c1
    scenario += c1.create(sp.record(groupId = "testing123", minSignerRequire = 2, adminAddress = sp.address("tz1235466..")))