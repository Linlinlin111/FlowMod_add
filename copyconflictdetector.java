package net.floodlightcontroller.conflictdetector;

//net.floodlightcontroller.conflictdetector.ConflictDetector


//支持OF1.0


import com.google.common.util.concurrent.ListenableFuture;
import com.sun.xml.internal.bind.v2.runtime.unmarshaller.XsiNilLoader;
import net.floodlightcontroller.core.*;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.SingletonTask;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.threadpool.IThreadPoolService;
import net.floodlightcontroller.topology.NodePortTuple;
import net.floodlightcontroller.util.OFMessageDamper;

import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.match.Match.Builder;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TableId;

import java.util.*;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class copyconflictdetector implements
        IFloodlightModule,
        IOFMessageListener
{

    private IFloodlightProviderService floodlightProvider;
    private IOFSwitchService switchService;
    private IThreadPoolService threadpool;

    private int packet_in_count = 0;

    // singeleton tasks
//    private SingletonTask resetPacketINCount;
    private SingletonTask updateSwitchState;

    private ArrayList<String> tableRules;
    private Map<String,String> flow_table;
        
    // task execute intervals
    private int PKT_COUNT_UPDATE_INTERVAL = 1;
    private int SWITCH_STATE_UPDATE_INTERVAL = 5;
    private int WAIT_START = 10;
//    private Map<DatapathId, Map<OFPort, Double>> lastFlowBytes;
//    private Map<DatapathId, Map<OFPort, Double>> newFlowSpeed;


    private final Object lock = new Object();
//    private double band_width = 10.0 * 1024 * 1024 / 8;

    
// protected OFMessageDamper messageDamper;
//	protected static int OFMESSAGE_DAMPER_CAPACITY = 10000; // TODO: find sweet spot
//	protected static int OFMESSAGE_DAMPER_TIMEOUT = 250; // ms
	
    /**
     * Return the list of interfaces that this module implements.
     * All interfaces must inherit IFloodlightService
     *
     * @return
     */
    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        return null;
    }

    /**
     * Instantiate (as needed) and return objects that implement each
     * of the services exported by this module.  The map returned maps
     * the implemented service to the object.  The object could be the
     * same object or different objects for different exported services.
     *
     * @return The map from service interface class to service implementation
     */
    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        return null;
    }

    /**
     * Get a list of Modules that this module depends on.  The module system
     * will ensure that each these dependencies is resolved before the
     * subsequent calls to init().
     *
     * @return The Collection of IFloodlightServices that this module depends
     * on.
     */
    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        Collection<Class<? extends IFloodlightService>> l =
                new ArrayList<>();
        l.add(IFloodlightProviderService.class);
        l.add(IOFSwitchService.class);
        return null;
    }

    /**
     * This is a hook for each module to do its <em>internal</em> initialization,
     * e.g., call setService(context.getService("Service"))
     * <p/>
     * All module dependencies are resolved when this is called, but not every module
     * is initialized.
     *
     * @param context
     * @throws net.floodlightcontroller.core.module.FloodlightModuleException
     */
    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        switchService = context.getServiceImpl(IOFSwitchService.class);
        threadpool = context.getServiceImpl(IThreadPoolService.class);
        tableRules=new ArrayList<String>();
        flow_table=new HashMap<>();
//        lastFlowBytes = new HashMap<>();
//        newFlowSpeed = new HashMap<>();
//        messageDamper = new OFMessageDamper(OFMESSAGE_DAMPER_CAPACITY,
//				EnumSet.of(OFType.FLOW_MOD),
//				OFMESSAGE_DAMPER_TIMEOUT);
    }

    /**
     * This is a hook for each module to do its <em>external</em> initializations,
     * e.g., register for callbacks or query for state in other modules
     * <p/>
     * It is expected that this function will not block and that modules that want
     * non-event driven CPU will spawn their own threads.
     *
     * @param context
     * @throws net.floodlightcontroller.core.module.FloodlightModuleException
     */
    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
//        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
//        floodlightProvider.addOFMessageListener(OFType.STATS_REPLY, this);
//    	floodlightProvider.addOFMessageListener(OFType.FLOW_REMOVED, this);
    	floodlightProvider.addOFMessageListener(OFType.PACKET_OUT, this);
        Runnable getSwitchState = new Runnable() {
            @Override
            public void run() {
                for (DatapathId id : switchService.getAllSwitchDpids()) {
                    updateSwitchInfo(id);
                }
                updateSwitchState.reschedule(SWITCH_STATE_UPDATE_INTERVAL, TimeUnit.SECONDS);
            }
        };
        ScheduledExecutorService ses = threadpool.getScheduledExecutor();
        updateSwitchState = new SingletonTask(ses, getSwitchState);
        updateSwitchState.reschedule(WAIT_START, TimeUnit.SECONDS);
    }

    private void updateSwitchInfo(DatapathId swid) {
        IOFSwitch sw = switchService.getSwitch(swid);
         if(sw!=null){
             OFFactory factory = sw.getOFFactory();
             OFFlowStatsRequest.Builder flow_state
                        =factory.buildFlowStatsRequest();
            flow_state.setTableId(TableId.ALL);
            
            
            try {
                ListenableFuture<List<OFFlowStatsReply>> future
                        = sw.writeStatsRequest(flow_state.build());
                List<OFFlowStatsReply> replies = future.get();

                for (OFFlowStatsReply reply : replies) {
                	if(reply.getEntries().size()!=0)
                            for(OFFlowStatsEntry entry:reply.getEntries()){
                         
//                                entry.getTableId();
         //                      Match mb= entry.getMatch();
//                               System.out.println(mb.toString());
                                String action=entry.getActions().toString();
                              

                                action=getAction(action);
                     

                                String s=entry.getMatch().toString();
                             
                                String eth_type=getEthType(s);
                               
                                if(eth_type.equals("800")){

                                	String src=getSrc(s);
                                	String dst=getDst(s);
                                	String result=sw.getId().toString()+":"+src+":"+dst;

                                	if(!tableRules.contains(result)){
                                		tableRules.add(result);
                                		flow_table.put(result, action);
                                	}
                                	else{
                                		if(flow_table.get(result)!=null){
                                			String ac=flow_table.get(result);
                                			if(!ac.equals(action)){
                                				System.out.println("*************		Conflicting!		****************");
                                				TableId tid= entry.getTableId();
                                				System.out.println(entry.getTableId());
//                                				OFFlowMod.Builder fmb=sw.getOFFactory().buildFlowDelete();
//                                				fmb.setTableId(tid);
//                                				boolean dampened = messageDamper.write(sw, fmb.build());
//                                				System.out.println(dampened);
                          
                                			}
                                		}
                                	}

                                }
                            
                            }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
     
            System.out.println("changdu             :"+flow_table.size());
         for(Map.Entry<String, String> entry:flow_table.entrySet()){
        	 System.out.println(entry.getKey()+":"+entry.getValue());
         }
        }
    }
    
    private String getEthType(String s){
   	 int loc=s.indexOf("eth_type");
     int begin=loc+9;
     int end=loc+12;
     String type=s.substring(begin, end);
    
        return type;
    }
    
    private String getSrc(String s){
      	 int loc=s.indexOf("ipv4_src");
         int begin=loc+9;
         int end=loc+17;
         String srcip=s.substring(begin, end);
        
            return srcip;
    }
    private String getDst(String s){	
     	 int loc=s.indexOf("ipv4_dst");
         int begin=loc+9;
         int end=loc+17;
         String dstip=s.substring(begin, end);
        
            return dstip;
    }
    private String getAction(String ac){

    	 int loc=ac.indexOf("port");
         int begin=loc+5;
         int end=loc+6;
         String action=ac.substring(begin, end);
    	return action;
    	
    }
   private String getInport(String[] in){
	   String inport;
	   inport=in[0];
	   String tm[]=inport.split("=");
	   inport=tm[1];
	   return inport;
   }

    /* ***********************
     * IOFMessageListener ****
     * ***********************/

/*
    private void processPacketIn(IOFSwitch sw, OFPacketIn msg, FloodlightContext cntx) {
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
        IPacket pkt = eth.getPayload();
        if (sw.getId().getLong() == 1L
            && pkt instanceof IPv4) {
            IPv4 ip_pkt = (IPv4)pkt;
            if (ip_pkt.getPayload() instanceof UDP) {
                synchronized (lock) {
                    packet_in_count++;
                }
            }
        }
    }*/

    /**
     * This is the method Floodlight uses to call listeners with OpenFlow messages
     *
     * @param sw   the OpenFlow switch that sent this message
     * @param msg  the message
     * @param cntx a Floodlight message context object you can use to pass
     *             information between listeners
     * @return the command to continue or stop the execution
     */
    @Override
    public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
    /*    switch(msg.getType()) {
            case PACKET_IN:
                processPacketIn(sw, (OFPacketIn) msg, cntx);
            default:
                break;
        }*/
    System.out.println("/////////////							/////////////			");
    
        return Command.CONTINUE;
    }

    /**
     * The name assigned to this listener
     *
     * @return
     */
    @Override
    public String getName() {
        return this.getClass().getSimpleName();
    }

    /**
     * Check if the module called name is a callback ordering prerequisite
     * for this module.  In other words, if this function returns true for
     * the given name, then this listener will be called after that
     * message listener.
     *
     * @param type the object type to which this applies
     * @param name the name of the module
     * @return whether name is a prerequisite.
     */
    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        return (type.equals(OFType.PACKET_IN) &&
                (name.equals("topology") || name.equals("devicemanager")));
    }

    /**
     * Check if the module called name is a callback ordering post-requisite
     * for this module.  In other words, if this function returns true for
     * the given name, then this listener will be called before that
     * message listener.
     *
     * @param type the object type to which this applies
     * @param name the name of the module
     * @return whether name is a post-requisite.
     */
    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        return false;
    }


}
