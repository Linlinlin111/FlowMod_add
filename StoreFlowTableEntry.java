package net.floodlightcontroller.conflictdetector;



//net.floodlightcontroller.conflictdetector.StoreFlowTableEntry


import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFFlowStatsEntry;
import org.projectfloodlight.openflow.protocol.OFFlowStatsReply;
import org.projectfloodlight.openflow.protocol.OFFlowStatsRequest;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.TableId;

import com.google.common.util.concurrent.ListenableFuture;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.SingletonTask;
import net.floodlightcontroller.threadpool.IThreadPoolService;
import net.floodlightcontroller.util.OFMessageDamper;

public class  StoreFlowTableEntry implements IFloodlightModule,IOFMessageListener,getStoreFlowTableEntryService{
	
    private IFloodlightProviderService floodlightProvider;
    private IOFSwitchService switchService;
    private IThreadPoolService threadpool;
    
    
    private SingletonTask updateSwitchState;

    private ArrayList<String> tableRules;
    private Map<String,String> flow_table;
    
    private int SWITCH_STATE_UPDATE_INTERVAL = 5;
    private int WAIT_START = 10;
    
    
    protected OFMessageDamper messageDamper;
   	protected static int OFMESSAGE_DAMPER_CAPACITY = 10000; // TODO: find sweet spot
   	protected static int OFMESSAGE_DAMPER_TIMEOUT = 250; // ms
   	
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return "detectbreforeadd";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		// TODO Auto-generated method stub
		
		System.out.println(msg.toString() + "    fenglin");
		return Command.CONTINUE;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(getStoreFlowTableEntryService.class);
	    return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		Map<Class<? extends IFloodlightService>, IFloodlightService> m = new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
	    m.put(getStoreFlowTableEntryService.class, this);
	    return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> l =
                new ArrayList<>();
        l.add(IFloodlightProviderService.class);
        l.add(IOFSwitchService.class);
        return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
        switchService = context.getServiceImpl(IOFSwitchService.class);
        threadpool = context.getServiceImpl(IThreadPoolService.class);
        tableRules=new ArrayList<String>();
        flow_table=new HashMap<>();
//        lastFlowBytes = new HashMap<>();
//        newFlowSpeed = new HashMap<>();
        messageDamper = new OFMessageDamper(OFMESSAGE_DAMPER_CAPACITY,
				EnumSet.of(OFType.FLOW_MOD),
				OFMESSAGE_DAMPER_TIMEOUT);
		
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProvider.addOFMessageListener(OFType.FLOW_MOD, this);
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
                         
                                String action=entry.getActions().toString();
                              
                                int priority=entry.getPriority();
                                action=getAction(action);
                     

                                String s=entry.getMatch().toString();
                             
                                String eth_type=getEthType(s);
                               
                                if(eth_type.equals("800")){

                                	String src=getSrc(s);
                                	String dst=getDst(s);
                                	String result=sw.getId().toString()+":"+priority+":"+src+":"+dst;

                                	if(!tableRules.contains(result)){
                                		tableRules.add(result);
                                		flow_table.put(result, action);
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
	    	 String[] tp1=s.split(",");
	  	   	 String[] tp2;
	  	     String[] tp3;
	  	     String srcip="";
	  	     for (int i =0;i<tp1.length;i++){
	  	    	 if(tp1[i].contains("ipv4_src")){
	  	    		 tp2=tp1[i].split("/");
	  	    		 tp3=tp2[0].split("=");
	  	    		 srcip=tp3[1].replace(")","");
	  	    		 return srcip;
	  	    	
	  	    	 }
	  	     }
	        
	            return srcip;
	    }
	    private String getDst(String s){	
	    	 String[] tp1=s.split(",");
	  	   	 String[] tp2;
	  	     String[] tp3;
	  	     String dstip="";
	  	     for (int i =0;i<tp1.length;i++){
	  	    	 if(tp1[i].contains("ipv4_dst")){
	  	    		 tp2=tp1[i].split("/");
	  	    		 tp3=tp2[0].split("=");
	  	    		 dstip=tp3[1].replace(")","");
	  	    		 return dstip;
	  	    		
	  	    	
	  	    	 }
	  	     }
	        
	            return dstip;
	    }
	    private String getAction(String ac){

	    	 int loc=ac.indexOf("port");
	         int begin=loc+5;
	         int end=loc+6;
	         String action=ac.substring(begin, end);
	    	return action;
	    	
	    }

		@Override
		public Map<String, String> getStoreTableEntry() {
			// TODO Auto-generated method stub
			return flow_table;
		}

}
