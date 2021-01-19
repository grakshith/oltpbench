/******************************************************************************
 *  Copyright 2015 by OLTPBenchmark Project                                   *
 *                                                                            *
 *  Licensed under the Apache License, Version 2.0 (the "License");           *
 *  you may not use this file except in compliance with the License.          *
 *  You may obtain a copy of the License at                                   *
 *                                                                            *
 *    http://www.apache.org/licenses/LICENSE-2.0                              *
 *                                                                            *
 *  Unless required by applicable law or agreed to in writing, software       *
 *  distributed under the License is distributed on an "AS IS" BASIS,         *
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  *
 *  See the License for the specific language governing permissions and       *
 *  limitations under the License.                                            *
 ******************************************************************************/

package com.oltpbenchmark.benchmarks.ycsb.procedures;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import com.oltpbenchmark.api.Procedure;
import com.oltpbenchmark.api.SQLStmt;
import com.oltpbenchmark.benchmarks.ycsb.YCSBConstants;

import java.sql.ResultSet;
import java.util.*;
import java.security.*;

public class ReadModifyWriteRecord extends YCSBProcedure {
    public final SQLStmt selectStmt = new SQLStmt(
        "SELECT * FROM USERTABLE where YCSB_KEY=? FOR UPDATE"
    );
    public final SQLStmt updateAllStmt = new SQLStmt(
        "UPDATE USERTABLE SET FIELD1=?,FIELD2=?,FIELD3=?,FIELD4=?,FIELD5=?," +
        "FIELD6=?,FIELD7=?,FIELD8=?,FIELD9=?,FIELD10=? WHERE YCSB_KEY=?"
    );
	//FIXME: The value in ysqb is a byteiterator
    public void run(Connection conn, int keyname, String fields[], String results[]) throws SQLException {
        
        // Fetch it!
        PreparedStatement stmt = this.getPreparedStatement(conn, selectStmt);
        stmt.setInt(1, keyname);          
        ResultSet r = stmt.executeQuery();
        while (r.next()) {
        	for (int i = 0; i < YCSBConstants.NUM_FIELDS; i++)
        	    results[i] = r.getString(i+1);
        }
        r.close();
        
        // Update that mofo
        stmt = this.getPreparedStatement(conn, updateAllStmt);
        stmt.setInt(11, keyname);
        
        for (int i = 0; i < fields.length; i++) {
        	stmt.setString(i+1, fields[i]);
        }
        stmt.executeUpdate();

        try{
            if(debug==true){
				SQLStmt getChangeSet = new SQLStmt("SELECT key, hash, next FROM credereum_get_changeset();");
				PreparedStatement hash = this.getPreparedStatement(conn, getChangeSet);
				ResultSet result = hash.executeQuery();
				LOG.debug(result.toString());
				byte[] hash_bytes;
				HashMap<String, byte[]> node;

				HashMap<String,HashMap<String, byte[]> > oldTree = new HashMap<String,HashMap<String, byte[]> >();
				HashMap<String,HashMap<String, byte[]> > newTree = new HashMap<String,HashMap<String, byte[]> >();
				while(result.next()){
					String key = result.getString(1);
					hash_bytes = result.getBytes(2);
					node = new HashMap<String, byte[]>();
					node.put("hash", hash_bytes);
					boolean next = result.getBoolean(3);
					if(next){
						newTree.put(key, node);
					}
					else{
						oldTree.put(key, node);
					}
					
				}
				ArrayList<byte[]> hashes = new ArrayList<byte[]>();
				hashes.add(newTree.get("").get("hash"));
				hashes.add(oldTree.get("").get("hash"));
				LOG.debug("Got the hash for the changeset: "+hashes.toString());
				try{
					Signature rsa = Signature.getInstance("SHA256withRSA");
					rsa.initSign(priv);
					for(byte[] b:hashes){
						rsa.update(b);
					}
					byte[] signature = rsa.sign();
					LOG.debug(signature.toString());
					SQLStmt signatureSet = new SQLStmt(String.format("SELECT from credereum_sign_transaction(?,?);"));
                	PreparedStatement signedStatement = this.getPreparedStatement(conn, signatureSet);
                	signedStatement.setString(1, pub_key.toString());
                	signedStatement.setBytes(2, signature);
                	signedStatement.execute();
				}
				catch(Exception e){
					LOG.error("ERROR:",e);
				}
	
				conn.commit();
			}
        }
        catch(Exception e){
            LOG.error("ERROR:", e);
        }
    }

}
