#!/usr/bin/env python3
import argparse
import csv
import datetime
import time
import os

import snappi

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

CTRL_DEFAULT = "https://192.169.1.11:8443"
LAN_TE_DEFAULT = "192.169.1.14:5555"
WAN_TE_DEFAULT = "192.169.1.11:5555"

DEFAULT_PPS_SWEEP = [50_000, 100_000, 200_000, 400_000, 800_000, 1_200_000, 1_600_000]
DEFAULT_TEST_DURATION_S = 15.0
DEFAULT_PKT_SIZE_BYTES = 64

_LATENCY_DEBUG_PRINTED = False


def extract_latency_p99(flow_metric):
    global _LATENCY_DEBUG_PRINTED

    lat = getattr(flow_metric, "latency", None)
    if lat is None:
        if not _LATENCY_DEBUG_PRINTED:
            _LATENCY_DEBUG_PRINTED = True
        return None

    if not _LATENCY_DEBUG_PRINTED:
        attrs = [a for a in dir(lat) if not a.startswith("_")]
        print("Latency metric attributes on this generator:", attrs)
        _LATENCY_DEBUG_PRINTED = True

    for field in ("p99", "percentile_99", "p_99", "pctl_99"):
        if hasattr(lat, field):
            return getattr(lat, field)

    for field in ("max", "max_ms", "max_usec", "max_ns"):
        if hasattr(lat, field):
            return getattr(lat, field)

    return None


def start_traffic(api, flow_names):
    ctrl = api.control_state()
    ctrl.traffic.flow_transmit.flow_names = flow_names
    ctrl.traffic.flow_transmit.state = ctrl.traffic.flow_transmit.START
    api.set_control_state(ctrl)


def stop_traffic(api, flow_names):
    ctrl = api.control_state()
    ctrl.traffic.flow_transmit.flow_names = flow_names
    ctrl.traffic.flow_transmit.state = ctrl.traffic.flow_transmit.STOP
    api.set_control_state(ctrl)


def run_sweep(api, lan_loc, wan_loc, label, pps_values,
              duration_s=DEFAULT_TEST_DURATION_S,
              pkt_size_bytes=DEFAULT_PKT_SIZE_BYTES):
    results = []

    for pps in pps_values:
        print(f"\n===== PPS = {pps} =====")

        cfg = api.config()

        p_lan = cfg.ports.add(name="lan", location=lan_loc)
        p_wan = cfg.ports.add(name="wan", location=wan_loc)

        f = cfg.flows.add(name="nat_udp")
        f.tx_rx.port.tx_name = p_lan.name
        f.tx_rx.port.rx_names = [p_wan.name]

        f.size.fixed = pkt_size_bytes
        f.rate.pps = pps
        total_pkts = int(pps * duration_s)
        if total_pkts <= 0:
            total_pkts = 1
        f.duration.fixed_packets.packets = total_pkts
        f.metrics.enable = True
        eth, ip, udp, payload = f.packet.ethernet().ipv4().udp().custom()
        eth.src.value = "00:00:00:00:00:01"
        eth.dst.value = "00:00:00:00:00:02"

        ip.src.value = "10.0.10.2"
        ip.dst.value = "10.0.20.2"

        udp.src_port.values = [5000]
        udp.dst_port.values = [6000]

        payload.bytes = "616d6f6e677573" # amogus

        print("Pushing config...")
        api.set_config(cfg)

        print("Starting traffic...")
        start_traffic(api, [f.name])

        req = api.metrics_request()
        req.flow.flow_names = [f.name]

        start = datetime.datetime.now()
        last_time = start
        last_bytes_tx = 0
        last_bytes_rx = 0

        throughput_tx_samples = []
        throughput_rx_samples = []
        latency_p99_samples = []

        final_fm = None

        timeout_s = duration_s + 10.0

        while True:
            now = datetime.datetime.now()
            if (now - start).total_seconds() > timeout_s:
                print("Timeout waiting for flow to stop, forcing STOP")
                stop_traffic(api, [f.name])
                break

            metrics = api.get_metrics(req)
            if not metrics.flow_metrics:
                raise RuntimeError("No flow metrics returned from controller")
            fm = metrics.flow_metrics[0]
            final_fm = fm

            if hasattr(fm, "bytes_tx"):
                bytes_tx = fm.bytes_tx
                bytes_rx = fm.bytes_rx
            else:
                bytes_tx = fm.frames_tx * pkt_size_bytes
                bytes_rx = fm.frames_rx * pkt_size_bytes

            dt = (now - last_time).total_seconds()
            if dt > 0:
                d_bytes_tx = bytes_tx - last_bytes_tx
                d_bytes_rx = bytes_rx - last_bytes_rx
                if d_bytes_tx >= 0 and d_bytes_rx >= 0:
                    throughput_tx_samples.append(d_bytes_tx * 8.0 / dt / 1e6)
                    throughput_rx_samples.append(d_bytes_rx * 8.0 / dt / 1e6)

            last_time = now
            last_bytes_tx = bytes_tx
            last_bytes_rx = bytes_rx

            p99 = extract_latency_p99(fm)
            if p99 is not None:
                latency_p99_samples.append(p99)

            if fm.transmit == fm.STOPPED:
                print("Flow transmit state STOPPED")
                break

            time.sleep(0.5)

        stop_traffic(api, [f.name])

        if final_fm is None:
            raise RuntimeError("Never got final flow metrics")

        if final_fm.frames_tx == 0:
            loss_pct = 100.0
        else:
            loss_pct = max(
                0.0,
                (final_fm.frames_tx - final_fm.frames_rx)
                * 100.0
                / final_fm.frames_tx,
            )

        if final_fm.frames_rx == 0:
            print("WARNING: no packets received on WAN side. "
                  "Router/NAT probably not forwarding anything.")

        avg_tx = (
            sum(throughput_tx_samples) / len(throughput_tx_samples)
            if throughput_tx_samples
            else 0.0
        )
        avg_rx = (
            sum(throughput_rx_samples) / len(throughput_rx_samples)
            if throughput_rx_samples
            else 0.0
        )
        p99_tail = max(latency_p99_samples) if latency_p99_samples else None

        offered_mbps = pps * pkt_size_bytes * 8.0 / 1e6

        msg = (
            f"PPS={pps}: offered≈{offered_mbps:.1f} Mbit/s, "
            f"tx≈{avg_tx:.1f} Mbit/s, rx≈{avg_rx:.1f} Mbit/s, "
            f"loss={loss_pct:.3f}%"
        )
        if p99_tail is not None:
            msg += f", p99≈{p99_tail} (generator units)"
        else:
            msg += ", p99=N/A"
        print(msg)

        results.append(
            {
                "pps": pps,
                "offered_mbps": offered_mbps,
                "tx_mbps": avg_tx,
                "rx_mbps": avg_rx,
                "loss_pct": loss_pct,
                "p99": p99_tail if p99_tail is not None else "",
            }
        )

    return results


def save_csv(results, label):
    fname = f"results_{label}.csv"
    fieldnames = ["pps", "offered_mbps", "tx_mbps", "rx_mbps", "loss_pct", "p99"]
    with open(fname, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in results:
            w.writerow(row)
    print(f"Saved CSV results to {fname}")


def plot_results(results, label):
    loads = [r["offered_mbps"] for r in results]
    tx = [r["tx_mbps"] for r in results]
    rx = [r["rx_mbps"] for r in results]
    loss = [r["loss_pct"] for r in results]

    plt.figure()
    plt.plot(loads, tx, "o-", label=f"TX {label}")
    plt.plot(loads, rx, "s-", label=f"RX {label}")
    plt.xlabel("Offered load (Mbit/s)")
    plt.ylabel("Throughput (Mbit/s)")
    plt.title(f"Throughput vs load ({label})")
    plt.grid(True, which="both", linestyle=":")
    plt.legend()
    fname_tput = f"throughput_{label}.png"
    plt.savefig(fname_tput, dpi=150, bbox_inches="tight")
    print(f"Saved throughput plot to {fname_tput}")

    plt.figure()
    plt.plot(loads, loss, "o-")
    plt.xlabel("Offered load (Mbit/s)")
    plt.ylabel("Loss (%)")
    plt.title(f"Loss vs load ({label})")
    plt.grid(True, which="both", linestyle=":")
    fname_loss = f"loss_{label}.png"
    plt.savefig(fname_loss, dpi=150, bbox_inches="tight")
    print(f"Saved loss plot to {fname_loss}")

    lat_loads = []
    lat_p99 = []
    for r in results:
        if r["p99"] != "" and r["p99"] is not None:
            lat_loads.append(r["offered_mbps"])
            lat_p99.append(r["p99"])

    if lat_loads:
        plt.figure()
        plt.plot(lat_loads, lat_p99, "o-")
        plt.xlabel("Offered load (Mbit/s)")
        plt.ylabel("p99 latency (generator units)")
        plt.title(f"p99 latency vs load ({label})")
        plt.grid(True, which="both", linestyle=":")
        fname_lat = f"latency_p99_{label}.png"
        plt.savefig(fname_lat, dpi=150, bbox_inches="tight")
        print(f"Saved latency tail plot to {fname_lat}")
    else:
        print("No latency data collected; skipping latency plot.")


def main():
    parser = argparse.ArgumentParser(
        description="IXIA-C / snappi NAT benchmarking sweep"
    )
    parser.add_argument("--ctrl", default=CTRL_DEFAULT,
                        help=f"Controller URL (default: {CTRL_DEFAULT})")
    parser.add_argument("--lan-te", default=LAN_TE_DEFAULT,
                        help=f"LAN traffic engine location (default: {LAN_TE_DEFAULT})")
    parser.add_argument("--wan-te", default=WAN_TE_DEFAULT,
                        help=f"WAN traffic engine location (default: {WAN_TE_DEFAULT})")
    parser.add_argument("--label", default="dpdk-nat",
                        help="Label for this run (used in filenames)")
    parser.add_argument("--pps", nargs="*", type=int,
                        help="Override PPS sweep, e.g. --pps 100000 200000 400000")
    parser.add_argument("--duration", type=float,
                        default=DEFAULT_TEST_DURATION_S,
                        help=f"Test duration (seconds) per point (default: {DEFAULT_TEST_DURATION_S})")
    parser.add_argument("--pkt-size", type=int,
                        default=DEFAULT_PKT_SIZE_BYTES,
                        help=f"Packet size in bytes (default: {DEFAULT_PKT_SIZE_BYTES})")

    args = parser.parse_args()

    if args.pps:
        pps_values = args.pps
    else:
        pps_values = DEFAULT_PPS_SWEEP

    print("Using PPS sweep:", pps_values)
    print(f"Controller: {args.ctrl}")
    print(f"LAN TE   : {args.lan_te}")
    print(f"WAN TE   : {args.wan_te}")
    print(f"Label    : {args.label}")
    print(f"Duration : {args.duration}s, pkt_size={args.pkt_size} bytes")

    os.environ.setdefault("SNAPPI_DISABLE_VERSION_CHECK", "1")

    api = snappi.api(location=args.ctrl, verify=False)

    results = run_sweep(
        api=api,
        lan_loc=args.lan_te,
        wan_loc=args.wan_te,
        label=args.label,
        pps_values=pps_values,
        duration_s=args.duration,
        pkt_size_bytes=args.pkt_size,
    )

    save_csv(results, args.label)
    plot_results(results, args.label)


if __name__ == "__main__":
    main()

