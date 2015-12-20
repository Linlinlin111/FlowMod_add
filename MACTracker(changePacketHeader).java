package net.floodlightcontroller.mactracker;

import java.io.IOException;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFMatchBmap;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActionPushVlan;
import org.projectfloodlight.openflow.protocol.action.OFActionSetField;
import org.projectfloodlight.openflow.protocol.action.OFActionSetNwDst;
import org.projectfloodlight.openflow.protocol.action.OFActionSetNwSrc;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionApplyActions;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructions;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.match.Match.Builder;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.U64;
import org.projectfloodlight.openflow.types.VlanVid;
import org.python.antlr.PythonParser.print_stmt_return;

//import net.floodlightcontroller.conflictdetector.ConflicetDetectorService;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.OFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.SingletonTask;

import net.floodlightcontroller.core.IFloodlightProviderService;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.Set;

import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.threadpool.IThreadPoolService;
import net.floodlightcontroller.util.MatchUtils;
import net.floodlightcontroller.util.OFMessageDamper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.xml.internal.ws.policy.privateutil.PolicyUtils.Collections;


//net.floodlightcontroller.mactracker.MACTracker
public class MACTracker implements IOFMessageListener, IFloodlightModule {

	
	
	protected IFloodlightProviderService floodlightProvider;
	protected Set<Long> macAddresses;
	protected static Logger logger;
	protected OFMessageDamper messageDamper;
	private IOFSwitchService switchService;
	private IThreadPoolService threadpool;
	private SingletonTask updateSwitchState;
	
	private boolean flag;
	private boolean flag1;
	
	
    private int PKT_COUNT_UPDATE_INTERVAL = 1;
    private int SWITCH_STATE_UPDATE_INTERVAL = 5;
    private int WAIT_START = 10;
	
	
	protected static int OFMESSAGE_DAMPER_CAPACITY = 10000; // TODO: find sweet spot
	protected static int OFMESSAGE_DAMPER_TIMEOUT = 250; // ms
	
//	protected ConflicetDetectorService conflictProvider ;
	
	 private Map<String,String> flow_table;
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return MACTracker.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		//return (type.equals(OFType.PACKET_IN) && (name.equals("topology") || name.equals("devicemanager")||name.equals("forwarding")));
//		 return (type.equals(OFType.PACKET_IN) && name.equals("packetChange"));
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		 //return (type.equals(OFType.PACKET_IN) && name.equals("forwarding"));
		 return (name.equals("forwarding"));
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		 Collection<Class<? extends IFloodlightService>> l =
			        new ArrayList<Class<? extends IFloodlightService>>();
			    l.add(IFloodlightProviderService.class);
			    l.add(IOFSwitchService.class);
			    
//			    l.add(ConflicetDetectorService.class);
			    return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub
	    floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
//	    conflictProvider=context.getServiceImpl(ConflicetDetectorService.class);
	    switchService = context.getServiceImpl(IOFSwitchService.class);
	    threadpool = context.getServiceImpl(IThreadPoolService.class);
	    macAddresses = new ConcurrentSkipListSet<Long>();
	    logger = LoggerFactory.getLogger(MACTracker.class);
	    flow_table=new HashMap<>();
		messageDamper = new OFMessageDamper(OFMESSAGE_DAMPER_CAPACITY,
				EnumSet.of(OFType.FLOW_MOD),
				OFMESSAGE_DAMPER_TIMEOUT);
        flag=false;
	    flag1=false;

	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
//		floodlightProvider.addOFMessageListener(OFType.FLOW_MOD, this);
//		floodlightProvider.addOFMessageListener(OFType.TABLE_MOD, this);
//		floodlightProvider.addOFMessageListener(OFType.TABLE_STATUS, this);

		  ScheduledExecutorService ses = threadpool.getScheduledExecutor();

	        Runnable getSwitchState = new Runnable() {
	            @Override
	            public void run() {
	                for (DatapathId id : switchService.getAllSwitchDpids()) {
	                    updateSwitchInfo(id);
	                }
	                updateSwitchState.reschedule(SWITCH_STATE_UPDATE_INTERVAL, TimeUnit.SECONDS);
	            }
	        };
	        updateSwitchState = new SingletonTask(ses, getSwitchState);
	        updateSwitchState.reschedule(WAIT_START, TimeUnit.SECONDS);
	}

	 private void updateSwitchInfo(DatapathId swid) {
		 
		 
		 	
			String dpid="00:00:00:00:00:00:00:01";
			String dpid2="00:00:00:00:00:00:00:03";
			int in=1;
			int out=2;
			OFPort inport=null;
			OFPort outport=null;
			int srcIp =IPv4.toIPv4Address("10.0.0.1");
			int dstIp =IPv4.toIPv4Address("10.0.0.2");
			IPv4Address src=IPv4Address.of(srcIp);
			IPv4Address dst=IPv4Address.of(dstIp);
			
			MacAddress srcMac=MacAddress.of("00:00:00:00:00:01");
			MacAddress dstMac=MacAddress.of("00:00:00:00:00:02");
			
//			for(DatapathId id:switchService.getAllSwitchDpids()){
				
				if(swid.toString().equals(dpid)&&flag==false){
					
					OFSwitch sw=(OFSwitch) switchService.getSwitch(swid);
					inport=OFPort.of(in);//findPort(portList, in); //in=2
					outport=OFPort.of(out);//findPort(portList, out);//out=1

//					sendPortFlowMod(sw, inport, outport,30);
//					sendPortFlowMod(sw, outport, inport,40);
////					
//					sendArpFlowmod(sw, inport, src,dst,srcMac, dstMac,10,outport);
//					sendArpFlowmod(sw, outport, dst,src,dstMac, srcMac,11,inport);
//					
//					sendIpFlowmod(sw, src, dst, inport,outport, 20,srcMac,dstMac);					
//					sendIpFlowmod(sw, dst, src, outport,inport, 21,dstMac,srcMac);					
//					
					
					IPv4Address chip=IPv4Address.of("10.0.2.10");
					src=IPv4Address.of("10.0.1.10");
					dst=IPv4Address.of("10.0.1.20");
					 srcMac=MacAddress.of("00:00:00:00:00:01");
					 dstMac=MacAddress.of("00:00:00:00:00:02");
					sendDstChangemod(sw, src, dst,chip,20);
					
					

				
			}
			
				if(swid.toString().equals(dpid2)&&flag1==false){
					
					OFSwitch sw=(OFSwitch) switchService.getSwitch(swid);
					inport=OFPort.of(in);//findPort(portList, in); //in=2
					outport=OFPort.of(out);//findPort(portList, out);//out=1


					IPv4Address chip=IPv4Address.of("10.0.1.30");
					src=IPv4Address.of("10.0.1.10");
					dst=IPv4Address.of("10.0.2.10");
					 srcMac=MacAddress.of("00:00:00:00:00:01");
					 dstMac=MacAddress.of("00:00:00:00:00:04");
					sendSrcChangemod(sw, src, dst,chip, 20);			
					
					
					
					
				
			}
		
//			}
		 
		 
	 }
	 
	 private void sendSrcChangemod(OFSwitch sw, IPv4Address src, IPv4Address dst,IPv4Address chSrcip,
			 int i) {
			// TODO Auto-generated method stub
//		 OFActionPushVlan vlan=sw.getOFFactory().actions().pushVlan(EthType.VLAN_FRAME);
//		  org.projectfloodlight.openflow.protocol.action.OFActionSetVlanVid.Builder vv = sw.getOFFactory().actions().buildSetVlanVid();
//		  vv.setVlanVid(VlanVid.ofVlan(1));
		 
//		OFActionSetNwSrc aob = sw.getOFFactory().actions().setNwSrc(chSrcip);
//		OFActionSetField sf=sw.getOFFactory().actions().setField(null);
//		sf.
		 OFActionOutput.Builder aob = sw.getOFFactory().actions().buildOutput();
		 aob.setPort(OFPort.ALL);
		 OFActionSetNwSrc.Builder sf=sw.getOFFactory().actions().buildSetNwSrc();
		 sf.setNwAddr(chSrcip);
		  List<OFAction> actions = new ArrayList<OFAction>();
//		 actions.add(vv.build());
		  actions.add(sf.build());
		  actions.add(aob.build());
		  System.out.println(actions.toString()+" 			00000");
		  Match.Builder  mb = sw.getOFFactory().buildMatch(); 
			 mb.setExact(MatchField.IPV4_SRC,src);
			 mb.setExact(MatchField.IPV4_DST,dst);
			 mb.setExact(MatchField.ETH_TYPE, EthType.IPv4);

		  System.out.println(actions.toString());
		  OFFlowMod.Builder fmb=sw.getOFFactory().buildFlowAdd();
		  fmb.setMatch(mb.build())
		  .setOutPort(OFPort.ALL)
		  .setActions(actions)
		  .setBufferId(OFBufferId.NO_BUFFER)
		  .setPriority(50);
		  System.out.println(fmb.build().toString());
		  boolean dampened=false;
			try {
			   int OFMESSAGE_DAMPER_CAPACITY = 10000; // TODO: find sweet spot
			  int OFMESSAGE_DAMPER_TIMEOUT = 250; // ms
				OFMessageDamper messageDamper;
				messageDamper = new OFMessageDamper(OFMESSAGE_DAMPER_CAPACITY,
						EnumSet.of(OFType.FLOW_MOD),
						OFMESSAGE_DAMPER_TIMEOUT);
				dampened = messageDamper.write(sw, fmb.build());
				flag1=true;
				System.out.println(dampened);
				sw.flush();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		}
	 
private void sendDstChangemod(OFSwitch sw, IPv4Address src, IPv4Address dst,IPv4Address chDstip,
			int i) {
		// TODO Auto-generated method stub
//	OFActionSetNwDst aob = sw.getOFFactory().actions().setNwDst(chDstip);
	 OFActionOutput.Builder aob = sw.getOFFactory().actions().buildOutput();
	 aob.setPort(OFPort.ALL);
	OFActionSetNwDst.Builder sf = sw.getOFFactory().actions().buildSetNwDst();
	 sf.setNwAddr(chDstip);
	  List<OFAction> actions = new ArrayList<OFAction>();
	  actions.add(sf.build());
	  actions.add(aob.build());
	  Match.Builder  mb = sw.getOFFactory().buildMatch(); 
		 mb.setExact(MatchField.IPV4_SRC,src);
		 mb.setExact(MatchField.IPV4_DST,dst);
		 mb.setExact(MatchField.ETH_TYPE, EthType.IPv4);

	  System.out.println(actions.toString());
	  OFFlowMod.Builder fmb=sw.getOFFactory().buildFlowAdd();
	  fmb.setMatch(mb.build())
	  .setOutPort(OFPort.ALL)
	  .setActions(actions)
	  .setBufferId(OFBufferId.NO_BUFFER)
	  .setPriority(50);
	  System.out.println(fmb.build().toString());
	  boolean dampened=false;
		try {
		   int OFMESSAGE_DAMPER_CAPACITY = 10000; // TODO: find sweet spot
		  int OFMESSAGE_DAMPER_TIMEOUT = 250; // ms
			OFMessageDamper messageDamper;
			messageDamper = new OFMessageDamper(OFMESSAGE_DAMPER_CAPACITY,
					EnumSet.of(OFType.FLOW_MOD),
					OFMESSAGE_DAMPER_TIMEOUT);
			dampened = messageDamper.write(sw, fmb.build());
			flag=true;
			System.out.println(dampened);
			sw.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

private void sendArpFlowmod(OFSwitch sw,OFPort inport,IPv4Address srcip,IPv4Address dstip,MacAddress srcmac,MacAddress dstmac,int priority,OFPort port){
	
//	Ethernet l2 = new Ethernet();
//	l2.setSourceMACAddress(srcmac);
//	l2.setDestinationMACAddress(MacAddress.BROADCAST);
//	short TYPE_ARP = 0x0806;
//	l2.setEtherType(TYPE_ARP);
//////	l2.setEtherType("0x0800");
//////	l2.setEtherType(EthType.IPv4);
//	IPv4 l3 = new IPv4();
////
//	l3.setSourceAddress(srcip);
//	l3.setDestinationAddress(dstip);
//	l3.setTtl((byte) 64);
////	l2.setPayload(l3);
//	Data l7 = new Data();
//	l7.setData(new byte[1000]);
//	
//	l2.setPayload(l3);
//	l3.setPayload(l7);
////	l4.setPayload(l7);
//	System.out.println(l2.toString()+" 						中特 ");
//	byte[] serializedData = l2.serialize();
//	
//	 OFActionOutput.Builder aob = sw.getOFFactory().actions().buildOutput();
//	 aob.setPort(OFPort.FLOOD);
//	 aob.setMaxLen(Integer.MAX_VALUE);
//	 List<OFAction> actions = new ArrayList<OFAction>();
//	 actions.add(aob.build());
//	
//	
//	OFPacketOut po = sw.getOFFactory().buildPacketOut() /* mySwitch is some IOFSwitch object */
//		    .setData(serializedData)
//		    .setActions(actions)
//		    .setInPort(OFPort.CONTROLLER)
//		    .build();
//		  
//		sw.write(po);
	Match.Builder  mb = sw.getOFFactory().buildMatch(); 
	mb.setExact(MatchField.ETH_TYPE, EthType.ARP)
//	.setExact(MatchField., arg1)
	.setExact(MatchField.IN_PORT, inport)
	.setExact(MatchField.ETH_SRC, srcmac)
	.setExact(MatchField.ETH_DST, dstmac);
	 OFActionOutput.Builder aob = sw.getOFFactory().actions().buildOutput();
	 aob.setPort(port);
	 aob.setMaxLen(Integer.MAX_VALUE);
	 List<OFAction> actions = new ArrayList<OFAction>();
	 actions.add(aob.build());
	 OFFlowMod.Builder fmb=sw.getOFFactory().buildFlowAdd();
		fmb.setMatch(mb.build())
		.setActions(actions)
		.setOutPort(port)
		.setIdleTimeout(100)
		.setHardTimeout(100)
		.setCookie(U64.ZERO)
		//.setCookie(U64.parseHex("0020000000000000"))
		.setBufferId(OFBufferId.NO_BUFFER)
		.setPriority(priority)
	    .setBufferId(OFBufferId.NO_BUFFER);
		System.out.println(fmb.build());
		boolean dampened=false;
		try {
			dampened = messageDamper.write(sw, fmb.build());
			System.out.println(dampened);
			flag=true;
			sw.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	
	
}
private void sendIpFlowmod(OFSwitch sw,IPv4Address srcip,IPv4Address dstip,OFPort inport,OFPort port,int priority,MacAddress srcmac,MacAddress dstmac){
	Match.Builder  mb = sw.getOFFactory().buildMatch(); 
	 mb.setExact(MatchField.IPV4_SRC,srcip);
	 mb.setExact(MatchField.IPV4_DST,dstip);
	 mb.setExact(MatchField.ETH_TYPE, EthType.IPv4);
	 mb.setExact(MatchField.IN_PORT, inport)
//	 .setExact(MatchFie, arg1)
	 .setExact(MatchField.ETH_SRC, srcmac)
	.setExact(MatchField.ETH_DST, dstmac);
//	mb.setExact(MatchField.ETH_SRC, srcMac)
//	mb.setExact(MatchField.ETH_DST, dstMac);
	 System.out.println(mb.build());
	 OFActionOutput.Builder aob = sw.getOFFactory().actions().buildOutput();
	 aob.setPort(port);
	 aob.setMaxLen(Integer.MAX_VALUE);
	 List<OFAction> actions = new ArrayList<OFAction>();
	 actions.add(aob.build());
	 OFFlowMod.Builder fmb=sw.getOFFactory().buildFlowAdd();
		fmb.setMatch(mb.build())
		.setActions(actions)
		.setOutPort(port)
		.setIdleTimeout(100)
		.setHardTimeout(100)
		.setBufferId(OFBufferId.NO_BUFFER)
		.setPriority(priority)
		.setCookie(U64.ZERO)
	//	.setCookie(U64.parseHex("0020000000000000"))
	    .setBufferId(OFBufferId.NO_BUFFER);
		System.out.println(fmb.build());
		boolean dampened=false;
		try {
			dampened = messageDamper.write(sw, fmb.build());
			System.out.println(dampened);
			flag=true;
			sw.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
}
	 
 private boolean sendPortFlowMod(OFSwitch sw,OFPort inport,OFPort outport,int priority){
	 
	 Match.Builder  mb = sw.getOFFactory().buildMatch(); 
	 mb.setExact(MatchField.IN_PORT, inport);
	 
	 
	 OFActionOutput.Builder aob = sw.getOFFactory().actions().buildOutput();
	 List<OFAction> actions = new ArrayList<OFAction>();
		aob.setPort(outport);
		aob.setMaxLen(Integer.MAX_VALUE);
		actions.add(aob.build());
		OFFlowMod.Builder fmb=sw.getOFFactory().buildFlowAdd();
		fmb.setMatch(mb.build())
		.setActions(actions)
		.setOutPort(outport)
		.setIdleTimeout(100)
		.setHardTimeout(100)
		.setBufferId(OFBufferId.NO_BUFFER)
		.setPriority(priority)
	    .setBufferId(OFBufferId.NO_BUFFER);
		System.out.println(fmb.build());
		boolean dampened=false;
		try {
			dampened = messageDamper.write(sw, fmb.build());
			System.out.println(dampened);
			flag=true;
			sw.flush();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return dampened;
	 
 }
 
	 @Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		// TODO Auto-generated method stub
		 System.out.println("MACTracker~~~~~~~~~~~~~~~~~~~~~~");

		 String dpid="00:00:00:00:00:00:00:01";
			int in=1;
			int out=2;
			OFPort inport=null;
			OFPort outport=null;
			int srcIp =IPv4.toIPv4Address("10.0.0.1");
			int dstIp =IPv4.toIPv4Address("10.0.0.2");
			IPv4Address src=IPv4Address.of(srcIp);
			IPv4Address dst=IPv4Address.of(dstIp);
			
			MacAddress srcMac=MacAddress.of("00:00:00:00:00:01");
			MacAddress dstMac=MacAddress.of("00:00:00:00:00:02");
			
		Ethernet eth =
                IFloodlightProviderService.bcStore.get(cntx,
                                            IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
//		 System.out.println(eth.getEtherType()+" ********");
//        Long sourceMACHash = eth.getSourceMACAddress().getLong();
		
		MacAddress srcac = eth.getSourceMACAddress();
		MacAddress dstac = eth.getDestinationMACAddress();
		

//		System.out.println(eth.toString());
        if(eth.getEtherType()==Ethernet.TYPE_IPv4){
        	
           IPv4 ipv4=(IPv4)eth.getPayload();
          System.out.println("Source IP:"+ipv4.getSourceAddress()+"	Destination IP: "+ipv4.getDestinationAddress());

          OFPacketIn pi=(OFPacketIn) msg;
//          System.out.println(pi.toString()+"             fl");
//          System.out.println(pi.get.toString()+"             fl");
        
         
          
          
          if (ipv4.getProtocol().equals(IpProtocol.TCP)) {
				TCP tcp = (TCP) ipv4.getPayload();

				System.out.println(IpProtocol.TCP+"		fld	 	"+tcp.getSourcePort()+ "		fld	 	"+tcp.getDestinationPort());
			} else if (ipv4.getProtocol().equals(IpProtocol.UDP)) {
				UDP udp = (UDP) ipv4.getPayload();
				System.out.println(IpProtocol.UDP+"		fld	 	"+udp.getSourcePort()+ "		fld	 	"+udp.getDestinationPort());
			}
          
//        	System.out.println(eth.toString());
//        	Builder mb = sw.getOFFactory().buildMatch();
//			mb.setExact(MatchField.IPV4_SRC, ipv4.getSourceAddress())
//			.setExact(MatchField.IPV4_DST, ipv4.getDestinationAddress())
//			.setExact(MatchField.ETH_TYPE, EthType.IPv4);
//			
////			OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
////			
//			List<OFAction> actions = new ArrayList<OFAction>();
//			OFActionOutput.Builder aob = sw.getOFFactory().actions().buildOutput();
//			aob.setPort(OFPort.ofInt(1));
//			aob.setMaxLen(Integer.MAX_VALUE);
//			actions.add(aob.build());
////			actions.add(sw.getOFFactory().actions().output(arg0, arg1));
//			OFFlowMod.Builder fmb=sw.getOFFactory().buildFlowAdd();
//			fmb.setMatch(mb.build())
//			.setActions(actions)
//			.setPriority(8)
//		    .setBufferId(OFBufferId.NO_BUFFER);
//			System.out.println(fmb.toString());
//			boolean dampened=false;
//			try {
//				dampened = messageDamper.write(sw, fmb.build());
//				flag=true;
//			//	sw.flush();
//			} catch (IOException e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}
//			System.out.println(dampened);
		

        }
//       
//
//        if (!macAddresses.contains(sourceMACHash)) {
//            macAddresses.add(sourceMACHash);
//            logger.info("MAC Address: {} seen on switch: {}",
//                    eth.getSourceMACAddress().toString(),
//                    sw.getId().toString());
//        }

        return Command.CONTINUE;
	}

	 
//		OFFlowMod.Builder fmb=sw.getOFFactory().buildFlowAdd();
//		OFFlowMod.Builder fmb1=sw.getOFFactory().buildFlowAdd();
//		
//		/*
//		 * OF1.0 设置操作为ACTION 以下
//		 */
//		OFActionOutput.Builder aob = sw.getOFFactory().actions().buildOutput();
//		OFActionOutput.Builder aob1 = sw.getOFFactory().actions().buildOutput();
//		List<OFAction> actions = new ArrayList<OFAction>();
//		List<OFAction> actions1 = new ArrayList<OFAction>();
//		aob.setPort(outport);
//		aob.setMaxLen(Integer.MAX_VALUE);
//		actions.add(aob.build());
//		
//		aob1.setPort(inport);
//		aob1.setMaxLen(Integer.MAX_VALUE);
//		actions1.add(aob1.build());
//		/*
//		 * 以上
//		 */
//		/*
//		 * OF1.3 设置操作为Instruction 以下
//		 */
//		
////		List<OFInstruction> acc=new ArrayList<OFInstruction>();
////		OFInstructionApplyActions.Builder ab=sw.getOFFactory().instructions().buildApplyActions();
////		ab.setActions(actions);
////		acc.add(ab.build());
//		/*
//		 * 以上
//		 */  
//		fmb.setMatch(mbb.build())
//		.setActions(actions)
//		.setOutPort(outport)
//		.setIdleTimeout(100)
//		.setHardTimeout(100)
//		.setBufferId(OFBufferId.NO_BUFFER)
//		.setPriority(1)
//	    .setBufferId(OFBufferId.NO_BUFFER);
//		
//		fmb1.setMatch(mbb1.build())
//		.setActions(actions1)
//		.setOutPort(inport)
//		.setIdleTimeout(100)
//		.setHardTimeout(100)
//		.setBufferId(OFBufferId.NO_BUFFER)
//		.setPriority(5)
//	    .setBufferId(OFBufferId.NO_BUFFER);
//		
//		System.out.println(fmb.build());
//		System.out.println(fmb1.build());
////		System.out.println(fmb.build().toString());
//		boolean dampened=false;
//		try {
//			dampened = messageDamper.write(sw, fmb.build());
//			System.out.println(dampened);
//			dampened=messageDamper.write(sw, fmb1.build());
//			System.out.println(dampened);
//			flag=true;
//			sw.flush();
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
		
	 
	 
}
