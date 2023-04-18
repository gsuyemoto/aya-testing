#![no_std]
#![no_main]
#![feature(ip_in_core)]

use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use core::mem;
use core::net::Ipv4Addr;

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)] // 
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; // 
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let addr_source = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let addr_dest = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    let addr_src_ip = Ipv4Addr::from(addr_source);
    let addr_src_octets = addr_src_ip.octets();
    let src_addr1 = addr_src_octets[0];
    let src_addr2 = addr_src_octets[1];

    let addr_dst_ip = Ipv4Addr::from(addr_dest);
    let addr_dst_octets = addr_dst_ip.octets();
    let dst_addr1 = addr_dst_octets[0];
    let dst_addr2 = addr_dst_octets[1];

    // info!(
    //     &ctx,
    //     "Src: {:ipv4} -- Dst: {:ipv4}", src_addr, dst_addr
    // );

    let action = if src_addr1 == 142u8 || dst_addr1 == 142u8 &&
                    src_addr2 == 250u8 || dst_addr2 == 250u8 
    {
        info!(
            &ctx,
            "Someone is accessing Youtube src: {:ipv4} -- dst: {:ipv4}", addr_source, addr_dest
        );

        xdp_action::XDP_DROP
    }
    else {
        xdp_action::XDP_PASS
    };

    Ok(action)
}

