/***************************************************************************
 *  Copyright (C) 2010 by H-Store Project                                  *
 *  Brown University                                                       *
 *  Massachusetts Institute of Technology                                  *
 *  Yale University                                                        *
 *                                                                         *
 *  Andy Pavlo (pavlo@cs.brown.edu)                                        *
 *  http://www.cs.brown.edu/~pavlo/                                        *
 *                                                                         *
 *  Visawee Angkanawaraphan (visawee@cs.brown.edu)                         *
 *  http://www.cs.brown.edu/~visawee/                                      *
 *                                                                         *
 *  Permission is hereby granted, free of charge, to any person obtaining  *
 *  a copy of this software and associated documentation files (the        *
 *  "Software"), to deal in the Software without restriction, including    *
 *  without limitation the rights to use, copy, modify, merge, publish,    *
 *  distribute, sublicense, and/or sell copies of the Software, and to     *
 *  permit persons to whom the Software is furnished to do so, subject to  *
 *  the following conditions:                                              *
 *                                                                         *
 *  The above copyright notice and this permission notice shall be         *
 *  included in all copies or substantial portions of the Software.        *
 *                                                                         *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,        *
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF     *
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. *
 *  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR      *
 *  OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,  *
 *  ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR  *
 *  OTHER DEALINGS IN THE SOFTWARE.                                        *
 ***************************************************************************/
package com.oltpbenchmark.benchmarks.auctionmark;

import java.io.File;
import java.sql.Connection;
import java.sql.Date;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;

import com.oltpbenchmark.benchmarks.auctionmark.AuctionMarkConstants.ItemStatus;
import com.oltpbenchmark.benchmarks.auctionmark.util.AuctionMarkUtil;
import com.oltpbenchmark.benchmarks.auctionmark.util.GlobalAttributeGroupId;
import com.oltpbenchmark.benchmarks.auctionmark.util.GlobalAttributeValueId;
import com.oltpbenchmark.benchmarks.auctionmark.util.ItemId;
import com.oltpbenchmark.benchmarks.auctionmark.util.ItemInfo;
import com.oltpbenchmark.benchmarks.auctionmark.util.UserId;
import com.oltpbenchmark.benchmarks.auctionmark.util.UserIdGenerator;
import com.oltpbenchmark.benchmarks.seats.SEATSConstants;
import com.oltpbenchmark.catalog.Catalog;
import com.oltpbenchmark.catalog.Table;
import com.oltpbenchmark.util.Histogram;
import com.oltpbenchmark.util.JSONUtil;
import com.oltpbenchmark.util.RandomDistribution.DiscreteRNG;
import com.oltpbenchmark.util.RandomDistribution.FlatHistogram;
import com.oltpbenchmark.util.RandomDistribution.Gaussian;
import com.oltpbenchmark.util.RandomDistribution.Zipf;
import com.oltpbenchmark.util.RandomGenerator;
import com.oltpbenchmark.util.SQLUtil;
import com.oltpbenchmark.util.StringUtil;


/**
 * AuctionMark Profile Information
 * @author pavlo
 */
public class AuctionMarkProfile {
    private static final Logger LOG = Logger.getLogger(AuctionMarkProfile.class);

    /**
     * We maintain a cached version of the profile that we will copy from
     * This prevents the need to have every single client thread load up a separate copy
     */
    private static AuctionMarkProfile cachedProfile;
    
    // ----------------------------------------------------------------
    // REQUIRED REFERENCES
    // ----------------------------------------------------------------
    
    /**
     * Specialized random number generator
     */
    protected final RandomGenerator rng;
    private final int num_clients;
    protected transient File data_directory;

    // ----------------------------------------------------------------
    // SERIALIZABLE DATA MEMBERS
    // ----------------------------------------------------------------

    /**
     * Database Scale Factor
     */
    protected double scale_factor;
    
    /**
     * The start time used when creating the data for this benchmark
     */
    protected Date benchmarkStartTime;
    
    /**
     * A histogram for the number of users that have the number of items listed
     * ItemCount -> # of Users
     */
    protected Histogram<Long> users_per_item_count = new Histogram<Long>();
    

    // ----------------------------------------------------------------
    // TRANSIENT DATA MEMBERS
    // ----------------------------------------------------------------
    
    protected final AuctionMarkBenchmark benchmark;
    
    /**
     * TableName -> TableCatalog
     */
    protected transient final Catalog catalog;
    
    /**
     * Histogram for number of items per category (stored as category_id)
     */
    protected Histogram<Long> item_category_histogram = new Histogram<Long>();

    /**
     * Three status types for an item:
     *  (1) Available - The auction of this item is still open
     *  (2) Ending Soon
     *  (2) Wait for Purchase - The auction of this item is still open. 
     *      There is a bid winner and the bid winner has not purchased the item.
     *  (3) Complete (The auction is closed and (There is no bid winner or
     *      the bid winner has already purchased the item)
     */
    private transient final LinkedList<ItemInfo> items_available = new LinkedList<ItemInfo>();
    private transient final LinkedList<ItemInfo> items_endingSoon = new LinkedList<ItemInfo>();
    private transient final LinkedList<ItemInfo> items_waitingForPurchase = new LinkedList<ItemInfo>();
    private transient final LinkedList<ItemInfo> items_completed = new LinkedList<ItemInfo>();
    
    /**
     * Internal list of GlobalAttributeGroupIds
     */
    protected transient List<GlobalAttributeGroupId> gag_ids = new ArrayList<GlobalAttributeGroupId>();

    /**
     * Internal map of UserIdGenerators
     */
    private transient final Map<Integer, UserIdGenerator> userIdGenerators = new HashMap<Integer, UserIdGenerator>();
    
    /** Random time different in seconds */
    public transient final DiscreteRNG randomTimeDiff;
    
    /** Random duration in days */
    public transient final Gaussian randomDuration;

    protected transient final Zipf randomNumImages;
    protected transient final Zipf randomNumAttributes;
    protected transient final Zipf randomPurchaseDuration;
    protected transient final Zipf randomNumComments;
    protected transient final Zipf randomInitialPrice;

    private transient FlatHistogram<Long> randomCategory;
    private transient FlatHistogram<Long> randomItemCount;
    
    /**
     * The last time that we called CHECK_WINNING_BIDS on this client
     */
    private transient Date lastCloseAuctionsTime;
    /**
     * When this client started executing
     */
    private Date clientStartTime;
    /**
     * Current Timestamp
     */
    private Date currentTime;
    
    /**
     * Keep track of previous waitForPurchase ItemIds so that we don't try to call NewPurchase
     * on them more than once
     */
    private transient Set<ItemInfo> previousWaitForPurchase = new HashSet<ItemInfo>();
    
    // -----------------------------------------------------------------
    // CONSTRUCTOR
    // -----------------------------------------------------------------

    /**
     * Constructor - Keep your pimp hand strong!
     */
    public AuctionMarkProfile(AuctionMarkBenchmark benchmark, RandomGenerator rng) {
        this.benchmark = benchmark;
        this.catalog = benchmark.getCatalog();
        this.rng = rng;
        this.scale_factor = benchmark.getWorkloadConfiguration().getScaleFactor();
        this.num_clients = benchmark.getWorkloadConfiguration().getTerminals();
        this.data_directory = benchmark.getDataDir();

        this.randomInitialPrice = new Zipf(this.rng, AuctionMarkConstants.ITEM_MIN_INITIAL_PRICE,
                                                     AuctionMarkConstants.ITEM_MAX_INITIAL_PRICE, 1.001);
        
        // Random time difference in a second scale
        this.randomTimeDiff = new Gaussian(this.rng, -AuctionMarkConstants.ITEM_PRESERVE_DAYS * 24 * 60 * 60,
                                                     AuctionMarkConstants.ITEM_MAX_DURATION_DAYS * 24 * 60 * 60);
        this.randomDuration = new Gaussian(this.rng, 1, AuctionMarkConstants.ITEM_MAX_DURATION_DAYS);
        this.randomPurchaseDuration = new Zipf(this.rng, 0, AuctionMarkConstants.ITEM_MAX_PURCHASE_DURATION_DAYS, 1.001);
        this.randomNumImages = new Zipf(this.rng,   AuctionMarkConstants.ITEM_MIN_IMAGES,
                                                    AuctionMarkConstants.ITEM_MAX_IMAGES, 1.001);
        this.randomNumAttributes = new Zipf(this.rng, AuctionMarkConstants.ITEM_MIN_GLOBAL_ATTRS,
                                                    AuctionMarkConstants.ITEM_MAX_GLOBAL_ATTRS, 1.001);
        this.randomNumComments = new Zipf(this.rng, AuctionMarkConstants.ITEM_MIN_COMMENTS,
                                                    AuctionMarkConstants.ITEM_MAX_COMMENTS, 1.001);

        
        // _lastUserId = this.getTableSize(AuctionMarkConstants.TABLENAME_USER);

        LOG.debug("AuctionMarkBenchmarkProfile :: constructor");
    }
    
    // -----------------------------------------------------------------
    // SERIALIZATION METHODS
    // -----------------------------------------------------------------

    protected final void saveProfile(Connection conn) throws SQLException {
        // CONFIG_PROFILE
        Table catalog_tbl = this.catalog.getTable(AuctionMarkConstants.TABLENAME_CONFIG_PROFILE);
        assert(catalog_tbl != null);
        PreparedStatement stmt = conn.prepareStatement(SQLUtil.getInsertSQL(catalog_tbl));
        int param_idx = 1;
        stmt.setObject(param_idx++, this.scale_factor); // CFP_SCALE_FACTOR
        stmt.setObject(param_idx++, this.benchmarkStartTime); // CFP_BENCHMARK_START
        stmt.setObject(param_idx++, this.users_per_item_count.toJSONString()); // CFP_USER_ITEM_HISTOGRAM
        int result = stmt.executeUpdate();
        assert(result == 1);

        if (LOG.isDebugEnabled())
            LOG.debug("Saving profile information into " + catalog_tbl);
        return;
    }
    
    private AuctionMarkProfile copyProfile(AuctionMarkProfile other) {
        this.scale_factor = other.scale_factor;
        this.benchmarkStartTime = other.benchmarkStartTime;
        this.users_per_item_count = other.users_per_item_count;
        this.item_category_histogram = other.item_category_histogram;
        this.gag_ids = other.gag_ids;
        this.previousWaitForPurchase = other.previousWaitForPurchase;
        
        this.items_available.addAll(other.items_available);
        Collections.shuffle(this.items_available);
        
        this.items_endingSoon.addAll(other.items_endingSoon);
        Collections.shuffle(this.items_endingSoon);
        
        this.items_waitingForPurchase.addAll(other.items_waitingForPurchase);
        Collections.shuffle(this.items_waitingForPurchase);
        
        this.items_completed.addAll(other.items_completed);
        Collections.shuffle(this.items_completed);
        
        return (this);
    }
    
    /**
     * Load the profile information stored in the database
     * @param 
     */
    protected synchronized void loadProfile(Connection conn) throws SQLException {
        // Check whether we have a cached Profile we can copy from
        if (cachedProfile != null) {
            if (LOG.isDebugEnabled()) LOG.debug("Using cached SEATSProfile");
            this.copyProfile(cachedProfile);
            return;
        }
        
        if (LOG.isDebugEnabled())
            LOG.debug("Loading AuctionMarkProfile for the first time");
        
        
        // Otherwise we have to go fetch everything again
        PreparedStatement stmt = null;
        ResultSet rs = null;
        
        // CONFIG_PROFILE
        stmt = conn.prepareStatement("SELECT * FROM " + SEATSConstants.TABLENAME_CONFIG_PROFILE);
        rs = stmt.executeQuery();
        this.loadConfigProfile(rs);
        
        // IMPORTANT: We need to set these timestamps here. It must be done
        // after we have loaded benchmarkStartTime
        this.setAndGetClientStartTime();
        this.updateAndGetCurrentTime();
        
        // ITEM CATEGORY COUNTS
        stmt = conn.prepareStatement("SELECT i_c_id, COUNT(i_id) FROM " + AuctionMarkConstants.TABLENAME_ITEM + " GROUP BY i_c_id");
        rs = stmt.executeQuery();
        this.loadItemCategoryCounts(rs);

        // ITEMS
        stmt = conn.prepareStatement("SELECT i_id, i_current_price, i_end_date, i_num_bids, i_status " +
                                     "  FROM " + AuctionMarkConstants.TABLENAME_ITEM + 
                                     " WHERE i_status = ? " +
                                     " ORDER BY i_iattr0 " +
                                     " LIMIT " + AuctionMarkConstants.ITEM_ID_CACHE_SIZE);
        for (ItemStatus status : ItemStatus.values()) {
            if (status.isInternal()) continue;
            int param = 1;
            stmt.setInt(param++, status.ordinal());
            rs = stmt.executeQuery();
            this.loadItems(rs, status);
        } // FOR
        
        // GLOBAL_ATTRIBUTE_GROUPS
        stmt = conn.prepareStatement("SELECT gag_id FROM " + AuctionMarkConstants.TABLENAME_GLOBAL_ATTRIBUTE_GROUP);
        rs = stmt.executeQuery();
        this.loadGlobalAttributeGroups(rs);
        
        cachedProfile = this;
    }
    
    private final void loadConfigProfile(ResultSet vt) throws SQLException {
        boolean adv = vt.next();
        assert(adv);
        int col = 1;
        this.scale_factor = vt.getDouble(col++);
        this.benchmarkStartTime = vt.getDate(col++);
        JSONUtil.fromJSONString(this.users_per_item_count, vt.getString(col++));
        
        if (LOG.isDebugEnabled())
            LOG.debug(String.format("Loaded %s data", AuctionMarkConstants.TABLENAME_CONFIG_PROFILE));
    }
    
    private final void loadItemCategoryCounts(ResultSet vt) throws SQLException {
        while (vt.next()) {
            int col = 1;
            long i_c_id = vt.getLong(col++);
            long count = vt.getLong(col++);
            this.item_category_histogram.put(i_c_id, count);
        } // WHILE
        if (LOG.isDebugEnabled())
            LOG.debug(String.format("Loaded %d item category records from %s",
                                    this.item_category_histogram.getValueCount(), AuctionMarkConstants.TABLENAME_ITEM));
    }
    
    private final void loadItems(ResultSet vt, ItemStatus status) throws SQLException {
        int ctr = 0;
        while (vt.next()) {
            int col = 1;
            ItemId i_id = new ItemId(vt.getLong(col++));
            double i_current_price = vt.getDouble(col++);
            Date i_end_date = vt.getDate(col++);
            int i_num_bids = (int)vt.getLong(col++);
            ItemStatus i_status = ItemStatus.get(vt.getLong(col++));
            assert(i_status == status);
            
            ItemInfo itemInfo = new ItemInfo(i_id, i_current_price, i_end_date, i_num_bids);
            this.addItemToProperQueue(itemInfo, false);
            ctr++;
        } // WHILE
        
        if (LOG.isDebugEnabled())
            LOG.debug(String.format("Loaded %d records from %s",
                                    ctr, AuctionMarkConstants.TABLENAME_ITEM));
    }
    
    private final void loadGlobalAttributeGroups(ResultSet vt) throws SQLException {
        while (vt.next()) {
            int col = 1;
            long gag_id = vt.getLong(col++);
            this.gag_ids.add(new GlobalAttributeGroupId(gag_id));
        } // WHILE
        if (LOG.isDebugEnabled())
            LOG.debug(String.format("Loaded %d records from %s",
                                    this.gag_ids.size(), AuctionMarkConstants.TABLENAME_GLOBAL_ATTRIBUTE_GROUP));
    }
    
    // -----------------------------------------------------------------
    // TIME METHODS
    // -----------------------------------------------------------------

    private Date getScaledCurrentTimestamp() {
        assert(this.clientStartTime != null);
        Date now = new Date(System.currentTimeMillis());
        Date time = AuctionMarkUtil.getScaledTimestamp(this.benchmarkStartTime, this.clientStartTime, now);
        if (LOG.isTraceEnabled())
            LOG.trace(String.format("Scaled:%d / Now:%d / BenchmarkStart:%d / ClientStart:%d",
                                   time.getTime(), now.getTime(), this.benchmarkStartTime.getTime(), this.clientStartTime.getTime()));
        return (time);
    }
    
    public synchronized Date updateAndGetCurrentTime() {
        this.currentTime = this.getScaledCurrentTimestamp();
        return this.currentTime;
    }
    public Date getCurrentTime() {
        return this.currentTime;
    }
    
    public Date setAndGetBenchmarkStartTime() {
        assert(this.benchmarkStartTime == null);
        this.benchmarkStartTime = new Date(System.currentTimeMillis());
        return (this.benchmarkStartTime);
    }
    public Date getBenchmarkStartTime() {
        return (this.benchmarkStartTime);
    }

    public Date setAndGetClientStartTime() {
        assert(this.clientStartTime == null);
        this.clientStartTime = new Date(System.currentTimeMillis());
        return (this.clientStartTime);
    }
    public Date getClientStartTime() {
        return (this.clientStartTime);
    }
    public boolean hasClientStartTime() {
        return (this.clientStartTime != null);
    }
    

    public synchronized Date updateAndGetLastCloseAuctionsTime() {
        this.lastCloseAuctionsTime = this.getScaledCurrentTimestamp();
        return this.lastCloseAuctionsTime;
    }
    public Date getLastCloseAuctionsTime() {
        return this.lastCloseAuctionsTime;
    }
    public boolean hasLastCloseAuctionsTime() {
        return (this.lastCloseAuctionsTime != null);
    }
    
    
    // -----------------------------------------------------------------
    // GENERAL METHODS
    // -----------------------------------------------------------------

    /**
     * Get the scale factor value for this benchmark profile
     * @return
     */
    public double getScaleFactor() {
        return (this.scale_factor);
    }
    /**
     * Set the scale factor for this benchmark profile
     * @param scale_factor
     */
    public void setScaleFactor(double scale_factor) {
        assert (scale_factor > 0) : "Invalid scale factor " + scale_factor;
        this.scale_factor = scale_factor;
    }
    
    // ----------------------------------------------------------------
    // USER METHODS
    // ----------------------------------------------------------------

    /**
     * 
     * @param min_item_count
     * @param client
     * @param skew
     * @param exclude
     * @return
     */
    private UserId getRandomUserId(int min_item_count, Integer client, boolean skew, UserId...exclude) {
        if (this.randomItemCount == null) {
            synchronized (this) {
                if (this.randomItemCount == null)
                    this.randomItemCount = new FlatHistogram<Long>(this.rng, this.users_per_item_count);
            } // SYNCH
        }
        
        // First grab the UserIdGenerator for the client (or -1 if there is no client)
        // and seek to that itemCount. We use the UserIdGenerator to ensure that we always 
        // select the next UserId for a given client from the same set of UserIds
        Integer client_idx = (client == null ? -1 : client);
        UserIdGenerator gen = this.userIdGenerators.get(client_idx);
        if (gen == null) {
            synchronized (this.userIdGenerators) {
                gen = this.userIdGenerators.get(client);
                if (gen == null) {
                    gen = new UserIdGenerator(this.users_per_item_count, this.num_clients, client);
                    this.userIdGenerators.put(client_idx, gen);
                }
            } // SYNCH
        }
        
        UserId user_id = null;
        int tries = 1000;
        while (user_id == null && tries-- > 0) {
            // We first need to figure out how many items our seller needs to have
            long itemCount = -1;
            assert(min_item_count < this.users_per_item_count.getMaxValue());
            while (itemCount < min_item_count) {
                itemCount = this.randomItemCount.nextValue();
            } // WHILE
        
            // Set the current item count and then choose a random position
            // between where the generator is currently at and where it ends
            synchronized (gen) {
                gen.setCurrentItemCount(itemCount);
                long position = rng.number(gen.getCurrentPosition(), gen.getTotalUsers());
                user_id = gen.seekToPosition(position);
            } // SYNCH
            if (user_id == null) continue;
            
            // Make sure that we didn't select the same UserId as the one we were
            // told to exclude.
            if (exclude != null && exclude.length > 0) {
                for (UserId ex : exclude) {
                    if (ex != null && ex.equals(user_id)) {
                        if (LOG.isTraceEnabled()) LOG.trace("Excluding " + user_id);
                        user_id = null;
                        break;
                    }
                } // FOR
                if (user_id == null) continue;
            }
            
            // If we don't care about skew, then we're done right here
            if (skew == false) {
                if (LOG.isTraceEnabled()) LOG.trace("Selected " + user_id);
                break;
            }
            if (LOG.isTraceEnabled()) LOG.trace("Skipping " + user_id);
            user_id = null;
        } // WHILE
        assert(user_id != null) : String.format("Failed to select a random UserId " +
                                                "[min_item_count=%d, client=%d, skew=%s, exclude=%s, totalPossible=%d, currentPosition=%d]",
                                                min_item_count, client, skew, Arrays.toString(exclude),
                                                gen.getTotalUsers(), gen.getCurrentPosition());
        
        return (user_id);
    }

    /**
     * Gets a random buyer ID for all clients
     * @return
     */
    public UserId getRandomBuyerId(UserId...exclude) {
        // We don't care about skewing the buyerIds at this point, so just get one from getRandomUserId
        return (this.getRandomUserId(0, null, false, exclude));
    }
    /**
     * Gets a random buyer ID for the given client
     * @return
     */
    public UserId getRandomBuyerId(int client, UserId...exclude) {
        // We don't care about skewing the buyerIds at this point, so just get one from getRandomUserId
        return (this.getRandomUserId(0, client, false, exclude));
    }
    /**
     * Get a random buyer UserId, where the probability that a particular user is selected
     * increases based on the number of bids that they have made in the past. We won't allow
     * the last bidder to be selected again
     * @param previousBidders
     * @return
     */
    public UserId getRandomBuyerId(Histogram<UserId> previousBidders, UserId...exclude) {
        // This is very inefficient, but it's probably good enough for now
        Histogram<UserId> new_h = new Histogram<UserId>(previousBidders);
        new_h.setKeepZeroEntries(false);
        for (UserId ex : exclude) new_h.removeAll(ex);
        new_h.put(this.getRandomBuyerId(exclude));
        try {
            LOG.trace("New Histogram:\n" + new_h);
        } catch (NullPointerException ex) {
            for (UserId user_id : new_h.values()) {
                System.err.println(String.format("%s => NEW:%s / ORIG:%s", user_id, new_h.get(user_id), previousBidders.get(user_id)));
            }
            throw ex;
        }
        
        FlatHistogram<UserId> rand_h = new FlatHistogram<UserId>(rng, new_h);
        return (rand_h.nextValue());
    }
    
    /**
     * Gets a random SellerID for the given client
     * @return
     */
    public UserId getRandomSellerId(int client) {
        return (this.getRandomUserId(1, client, true));
    }
    
    // ----------------------------------------------------------------
    // ITEM METHODS
    // ----------------------------------------------------------------
    
    private boolean addItem(LinkedList<ItemInfo> itemSet, ItemInfo itemInfo) {
        boolean added = false;
        synchronized (itemSet) {
            if (itemSet.contains(itemInfo)) {
                // HACK: Always swap existing ItemInfos with our new one, since it will
                // more up-to-date information
                int idx = itemSet.indexOf(itemInfo);
                ItemInfo existing = itemSet.set(idx, itemInfo);
                assert(existing != null);
                return (true);
            }
            if (itemInfo.hasCurrentPrice()) 
                assert(itemInfo.getCurrentPrice() > 0) : "Negative current price for " + itemInfo;
            
            // If we have room, shove it right in
            // We'll throw it in the back because we know it hasn't been used yet
            if (itemSet.size() < AuctionMarkConstants.ITEM_ID_CACHE_SIZE) {
                itemSet.addLast(itemInfo);
                added = true;
            
            // Otherwise, we can will randomly decide whether to pop one out
            } else if (this.rng.nextBoolean()) {
                itemSet.pop();
                itemSet.addLast(itemInfo);
                added = true;
            }
        } // SYNCH
        return (added);
    }
    private void removeItem(LinkedList<ItemInfo> itemSet, ItemInfo itemInfo) {
        synchronized (itemSet) {
            itemSet.remove(itemInfo);
        } // SYNCH
    }
    
    public synchronized void updateItemQueues() {
        // HACK
        Set<ItemInfo> all = new HashSet<ItemInfo>();
        @SuppressWarnings("unchecked")
        LinkedList<ItemInfo> itemSets[] = new LinkedList[]{
            this.items_available,
            this.items_endingSoon,
            this.items_waitingForPurchase,
            this.items_completed,
        };
        for (LinkedList<ItemInfo> list : itemSets) {
            synchronized (list) {
                all.addAll(list);
            } // SYNCH
        } // FOR
        
        Date currentTime = this.updateAndGetCurrentTime();
        assert(currentTime != null);
        if (LOG.isDebugEnabled()) LOG.debug("CurrentTime: " + currentTime);
        for (ItemInfo itemInfo : all) {
            this.addItemToProperQueue(itemInfo, false);
        } // FOR
        
        if (LOG.isDebugEnabled()) {
            Map<ItemStatus, Integer> m = new HashMap<ItemStatus, Integer>();
            m.put(ItemStatus.OPEN, this.items_available.size());
            m.put(ItemStatus.ENDING_SOON, this.items_endingSoon.size());
            m.put(ItemStatus.WAITING_FOR_PURCHASE, this.items_waitingForPurchase.size());
            m.put(ItemStatus.CLOSED, this.items_completed.size());
            LOG.debug(String.format("Updated Item Queues [%s]:\n%s",
                                    currentTime, StringUtil.formatMaps(m)));
        }
    }
    
    public ItemStatus addItemToProperQueue(ItemInfo itemInfo, boolean is_loader) {
        // Calculate how much time is left for this auction
        Date baseTime = (is_loader ? this.getBenchmarkStartTime() :
                                              this.getCurrentTime());
        assert(itemInfo.endDate != null);
        assert(baseTime != null) : "is_loader=" + is_loader;
        long remaining = itemInfo.endDate.getTime() - baseTime.getTime();
        ItemStatus ret;
        
        // Already ended
        if (remaining <= 100000) {
            if (itemInfo.numBids > 0 && itemInfo.status != ItemStatus.CLOSED) {
                synchronized (this.previousWaitForPurchase) {
                    if (this.previousWaitForPurchase.contains(itemInfo) == false) {
                        this.previousWaitForPurchase.add(itemInfo);
                        this.addItem(this.items_waitingForPurchase, itemInfo);
                    }
                } // SYNCH
                ret = ItemStatus.WAITING_FOR_PURCHASE;
            } else {
                this.addItem(this.items_completed, itemInfo);
                ret = ItemStatus.CLOSED;
            }
            this.removeAvailableItem(itemInfo);
            this.removeEndingSoonItem(itemInfo);
        }
        // About to end soon
        else if (remaining < AuctionMarkConstants.ENDING_SOON) {
            this.addItem(this.items_endingSoon, itemInfo);
            this.removeAvailableItem(itemInfo);
            ret = ItemStatus.ENDING_SOON;
        }
        // Still available
        else {
            this.addItem(this.items_available, itemInfo);
            ret = ItemStatus.OPEN;
        }
        
        if (LOG.isTraceEnabled())
            LOG.trace(String.format("%s - #%d [%s]", ret, itemInfo.itemId.encode(), itemInfo.getEndDate()));
        
        return (ret);
    }
    
    /**
     * 
     * @param itemSet
     * @param needCurrentPrice
     * @param needFutureEndDate TODO
     * @return
     */
    private ItemInfo getRandomItem(LinkedList<ItemInfo> itemSet, boolean needCurrentPrice, boolean needFutureEndDate) {
        ItemInfo itemInfo = null;
        Set<ItemInfo> seen = new HashSet<ItemInfo>();
        Date currentTime = this.updateAndGetCurrentTime();
        
        synchronized (itemSet) {
            int num_items = itemSet.size();
            int idx = -1;
            
            if (LOG.isTraceEnabled()) 
                LOG.trace(String.format("Getting random ItemInfo [numItems=%d, currentTime=%s, needCurrentPrice=%s]",
                                       num_items, currentTime, needCurrentPrice));
            long tries = 1000;
            while (num_items > 0 && tries-- > 0 && seen.size() < num_items) {
                idx = this.rng.nextInt(num_items);
                ItemInfo temp = itemSet.get(idx);
                assert(temp != null);
                if (seen.contains(temp)) continue;
                seen.add(temp);
                
                // Needs to have an embedded currentPrice
                if (needCurrentPrice && temp.hasCurrentPrice() == false) {
                    continue;
                }
                
                // If they want an item that is ending in the future, then we compare it with 
                // the current timestamp
                if (needFutureEndDate) {
                    boolean compareTo = (temp.getEndDate().compareTo(currentTime) < 0);
                    if (LOG.isTraceEnabled())
                        LOG.trace("CurrentTime:" + currentTime + " / EndTime:" + temp.getEndDate() + " [compareTo=" + compareTo + "]");
                    if (temp.hasEndDate() == false || compareTo) {
                        continue;
                    }
                }
                
                // Uniform
                itemInfo = temp;
                break;
            } // WHILE
            if (itemInfo == null) {
                if (LOG.isDebugEnabled()) LOG.debug("Failed to find ItemInfo [hasCurrentPrice=" + needCurrentPrice + ", needFutureEndDate=" + needFutureEndDate + "]");
                return (null);
            }
            assert(idx >= 0);
            
            // Take the item out of the set and insert back to the front
            // This is so that we can maintain MRU->LRU ordering
            itemSet.remove(idx);
            itemSet.addFirst(itemInfo);
        } // SYNCHRONIZED
        if (needCurrentPrice) {
            assert(itemInfo.hasCurrentPrice()) : "Missing currentPrice for " + itemInfo;
            assert(itemInfo.getCurrentPrice() > 0) : "Negative currentPrice '" + itemInfo.getCurrentPrice() + "' for " + itemInfo;
        }
        if (needFutureEndDate) {
            assert(itemInfo.hasEndDate()) : "Missing endDate for " + itemInfo;
        }
        return itemInfo;
    }
    
    /**********************************************************************************************
     * AVAILABLE ITEMS
     **********************************************************************************************/
    public void removeAvailableItem(ItemInfo itemInfo) {
        this.removeItem(this.items_available, itemInfo);
    }
    public ItemInfo getRandomAvailableItemId() {
        return this.getRandomItem(this.items_available, false, false);
    }
    public ItemInfo getRandomAvailableItem(boolean hasCurrentPrice) {
        return this.getRandomItem(this.items_available, hasCurrentPrice, false);
    }
    public int getAvailableItemsCount() {
        return this.items_available.size();
    }

    /**********************************************************************************************
     * ENDING SOON ITEMS
     **********************************************************************************************/
    public void removeEndingSoonItem(ItemInfo itemInfo) {
        this.removeItem(this.items_endingSoon, itemInfo);
    }
    public ItemInfo getRandomEndingSoonItem() {
        return this.getRandomItem(this.items_endingSoon, false, true);
    }
    public ItemInfo getRandomEndingSoonItem(boolean hasCurrentPrice) {
        return this.getRandomItem(this.items_endingSoon, hasCurrentPrice, true);
    }
    public int getEndingSoonItemsCount() {
        return this.items_endingSoon.size();
    }
    
    /**********************************************************************************************
     * WAITING FOR PURCHASE ITEMS
     **********************************************************************************************/
    public void removeWaitForPurchaseItem(ItemInfo itemInfo) {
        this.removeItem(this.items_waitingForPurchase, itemInfo);
    }
    public ItemInfo getRandomWaitForPurchaseItem() {
        return this.getRandomItem(this.items_waitingForPurchase, false, false);
    }
    public int getWaitForPurchaseItemsCount() {
        return this.items_waitingForPurchase.size();
    }

    /**********************************************************************************************
     * COMPLETED ITEMS
     **********************************************************************************************/
    public void removeCompleteItem(ItemInfo itemInfo) {
        this.removeItem(this.items_completed, itemInfo);
    }
    public ItemInfo getRandomCompleteItem() {
        return this.getRandomItem(this.items_completed, false, false);
    }
    public int getCompleteItemsCount() {
        return this.items_completed.size();
    }
    
    /**********************************************************************************************
     * ALL ITEMS
     **********************************************************************************************/
    public int getAllItemsCount() {
        return (this.getAvailableItemsCount() +
                this.getEndingSoonItemsCount() +
                this.getWaitForPurchaseItemsCount() +
                this.getCompleteItemsCount());
    }
    @SuppressWarnings("unchecked")
    public ItemInfo getRandomItem() {
        assert(this.getAllItemsCount() > 0);
        LinkedList<ItemInfo> itemSets[] = new LinkedList[]{
            this.items_available,
            this.items_endingSoon,
            this.items_waitingForPurchase,
            this.items_completed,
        };
        int idx = -1;
        while (idx == -1 || itemSets[idx].isEmpty()) {
            idx = rng.nextInt(itemSets.length);
        } // WHILE
        return (this.getRandomItem(itemSets[idx], false, false));
    }

    // ----------------------------------------------------------------
    // GLOBAL ATTRIBUTE METHODS
    // ----------------------------------------------------------------

    /**
     * Return a random GlobalAttributeValueId
     * @return
     */
    public synchronized GlobalAttributeValueId getRandomGlobalAttributeValue() {
        int offset = rng.nextInt(this.gag_ids.size());
        GlobalAttributeGroupId gag_id = this.gag_ids.get(offset);
        assert(gag_id != null);
        int count = rng.nextInt(gag_id.getCount());
        GlobalAttributeValueId gav_id = new GlobalAttributeValueId(gag_id, count);
        return gav_id;
    }
    
    public synchronized long getRandomCategoryId() {
        if (this.randomCategory == null) {
            this.randomCategory = new FlatHistogram<Long>(this.rng, this.item_category_histogram); 
        }
        return randomCategory.nextLong();
    }


    // -----------------------------------------------------------------
    // SERIALIZATION
    // -----------------------------------------------------------------

//    @Override
//    public void load(String input_path, Database catalog_db) throws IOException {
//        JSONUtil.load(this, catalog_db, input_path);
//    }
//
//    @Override
//    public void save(String output_path) throws IOException {
//        JSONUtil.save(this, output_path);
//    }
//
//    @Override
//    public String toJSONString() {
//        return (JSONUtil.toJSONString(this));
//    }
//
//    @Override
//    public void toJSON(JSONStringer stringer) throws JSONException {
//        JSONUtil.fieldsToJSON(stringer, this, AuctionMarkBenchmarkProfile.class, JSONUtil.getSerializableFields(this.getClass()));
//    }
//
//    @Override
//    public void fromJSON(JSONObject json_object, Database catalog_db) throws JSONException {
//        JSONUtil.fieldsFromJSON(json_object, catalog_db, this, AuctionMarkBenchmarkProfile.class, false, JSONUtil.getSerializableFields(this.getClass()));
//    }
}