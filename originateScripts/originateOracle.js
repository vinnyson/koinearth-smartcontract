import {TezosToolKit, TezosOperationError} from '@taquito/taquito';
import oracleCodeJSON from '../Contracts/Oracle/code.js';
import oracleStorageJSON from '../Contracts/Oracle/storage';

const Tezos = new TezosToolKit('https://delphinet-tezos.giganode.io');
const util = require("util");

Tezos.setSignerProvider(new InMemorySigner('edskRr8dPoqwy3qaRzPH1qYqpXf23oEsmQ93sPNzdAo1ZjUqSmFDz8j8PiZuHyiUKxaeTCoBEmagB2HDYXT1nUFDPwyJXTrGHq'));

export async function originateOracle(){
    try{
        console.log("Begin originating oracle contract");

        const originate_op = await Tezos.contract.originate({
            code: oracleCodeJSON,
            init: oracleStorageJSON,
        });

        const originated_oracle = await originate_op.contract();

        console.log("New contract address: " + originated_oracle.address);
        console.log("Oracle Contract successfully originated");
        return originated_oracle.address;
    } catch (e) {
        if (e instanceof TezosOperationError){
            console.log(util.inspect(e.errors, false, null, true));
        } else {
            console.log("Error ", e);
        }
    }
}

originateOracle();