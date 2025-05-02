--
-- PostgreSQL database dump
--

-- Dumped from database version 17.4 (Debian 17.4-1.pgdg120+2)
-- Dumped by pg_dump version 17.4 (Debian 17.4-1.pgdg120+2)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: acc_auth_logs; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.acc_auth_logs (
    id integer NOT NULL,
    "account_Number" character varying,
    mac character varying,
    gw_id character varying,
    stage character varying NOT NULL,
    date timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.acc_auth_logs OWNER TO wildweasel;

--
-- Name: acc_auth_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: wildweasel
--

CREATE SEQUENCE public.acc_auth_logs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.acc_auth_logs_id_seq OWNER TO wildweasel;

--
-- Name: acc_auth_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: wildweasel
--

ALTER SEQUENCE public.acc_auth_logs_id_seq OWNED BY public.acc_auth_logs.id;


--
-- Name: acc_details; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.acc_details (
    id integer NOT NULL,
    "account_Number" character varying,
    pword character varying,
    total_incoming_packets double precision,
    total_outgoing_packets double precision,
    last_active character varying
);


ALTER TABLE public.acc_details OWNER TO wildweasel;

--
-- Name: COLUMN acc_details.pword; Type: COMMENT; Schema: public; Owner: wildweasel
--

COMMENT ON COLUMN public.acc_details.pword IS 'depreciated';


--
-- Name: acc_details_id_seq; Type: SEQUENCE; Schema: public; Owner: wildweasel
--

CREATE SEQUENCE public.acc_details_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.acc_details_id_seq OWNER TO wildweasel;

--
-- Name: acc_details_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: wildweasel
--

ALTER SEQUENCE public.acc_details_id_seq OWNED BY public.acc_details.id;


--
-- Name: acc_sessions; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.acc_sessions (
    id integer NOT NULL,
    "account_Number" character varying,
    package character varying,
    limit_count integer,
    limit_type character varying,
    counter integer,
    incoming_packets double precision,
    outgoing_packets double precision,
    created_on timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    last_modified character varying
);


ALTER TABLE public.acc_sessions OWNER TO wildweasel;

--
-- Name: acc_sessions_id_seq; Type: SEQUENCE; Schema: public; Owner: wildweasel
--

CREATE SEQUENCE public.acc_sessions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.acc_sessions_id_seq OWNER TO wildweasel;

--
-- Name: acc_sessions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: wildweasel
--

ALTER SEQUENCE public.acc_sessions_id_seq OWNED BY public.acc_sessions.id;


--
-- Name: acc_transactions; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.acc_transactions (
    id integer NOT NULL,
    "account_Number" character varying,
    package character varying,
    vlanid character varying,
    gw_id character varying,
    gw_sn character varying,
    gw_address character varying,
    gw_port character varying,
    ssid character varying,
    apmac character varying,
    mac character varying,
    device character varying,
    ip character varying,
    token character varying,
    stage character varying,
    total_incoming_packets double precision,
    total_outgoing_packets double precision,
    created_on timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    last_active character varying
);


ALTER TABLE public.acc_transactions OWNER TO wildweasel;

--
-- Name: acc_transactions_id_seq; Type: SEQUENCE; Schema: public; Owner: wildweasel
--

CREATE SEQUENCE public.acc_transactions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.acc_transactions_id_seq OWNER TO wildweasel;

--
-- Name: acc_transactions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: wildweasel
--

ALTER SEQUENCE public.acc_transactions_id_seq OWNED BY public.acc_transactions.id;


--
-- Name: access_auth_logs; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.access_auth_logs (
    id integer NOT NULL,
    username character varying,
    stage character varying,
    gw_id character varying,
    date timestamp without time zone,
    mac character varying
);


ALTER TABLE public.access_auth_logs OWNER TO wildweasel;

--
-- Name: access_auth_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: wildweasel
--

CREATE SEQUENCE public.access_auth_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.access_auth_logs_id_seq OWNER TO wildweasel;

--
-- Name: access_auth_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: wildweasel
--

ALTER SEQUENCE public.access_auth_logs_id_seq OWNED BY public.access_auth_logs.id;


--
-- Name: accounting; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.accounting (
    username character varying NOT NULL,
    time_stamp bigint NOT NULL,
    acctstatustype character varying,
    acctsessionid character varying,
    nasidentifier character varying,
    auth_mode character varying,
    device character varying,
    acctinputoctets bigint,
    acctoutputoctets bigint,
    framedipaddress character varying,
    mac character varying,
    created_at timestamp with time zone
);


ALTER TABLE public.accounting OWNER TO wildweasel;

--
-- Name: admin_users; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.admin_users (
    id integer NOT NULL,
    username character varying,
    password character varying,
    first_name character varying,
    last_name character varying,
    role_id integer NOT NULL,
    mpop_id character varying NOT NULL,
    created_by_id integer,
    created_on character varying,
    modified_by_id integer,
    modified_on character varying
);


ALTER TABLE public.admin_users OWNER TO wildweasel;

--
-- Name: admin_users_id_seq; Type: SEQUENCE; Schema: public; Owner: wildweasel
--

CREATE SEQUENCE public.admin_users_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.admin_users_id_seq OWNER TO wildweasel;

--
-- Name: admin_users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: wildweasel
--

ALTER SEQUENCE public.admin_users_id_seq OWNED BY public.admin_users.id;


--
-- Name: alembic_version; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.alembic_version (
    version_num character varying(32) NOT NULL
);


ALTER TABLE public.alembic_version OWNER TO wildweasel;

--
-- Name: announcements; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.announcements (
    id integer NOT NULL,
    name character varying(64),
    path character varying(128),
    gw_id character varying NOT NULL,
    modified_by_id integer NOT NULL,
    modified_on character varying,
    status smallint,
    created_by_id integer NOT NULL,
    created_on character varying
);


ALTER TABLE public.announcements OWNER TO wildweasel;

--
-- Name: announcements_id_seq; Type: SEQUENCE; Schema: public; Owner: wildweasel
--

CREATE SEQUENCE public.announcements_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.announcements_id_seq OWNER TO wildweasel;

--
-- Name: announcements_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: wildweasel
--

ALTER SEQUENCE public.announcements_id_seq OWNED BY public.announcements.id;


--
-- Name: auto_complete; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.auto_complete (
    id integer NOT NULL,
    command character varying(255),
    device_model character varying(255),
    suggestion_list bytea
);


ALTER TABLE public.auto_complete OWNER TO wildweasel;

--
-- Name: certified; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.certified (
    id integer NOT NULL,
    mac character varying,
    common_name character varying,
    cert_data double precision,
    month_data double precision,
    last_record double precision,
    last_active character varying
);


ALTER TABLE public.certified OWNER TO wildweasel;

--
-- Name: certified_id_seq; Type: SEQUENCE; Schema: public; Owner: wildweasel
--

CREATE SEQUENCE public.certified_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.certified_id_seq OWNER TO wildweasel;

--
-- Name: certified_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: wildweasel
--

ALTER SEQUENCE public.certified_id_seq OWNED BY public.certified.id;


--
-- Name: client_auth_logs; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.client_auth_logs (
    id integer NOT NULL,
    uname character varying,
    stage character varying,
    gw_id character varying,
    date timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    mac character varying
);


ALTER TABLE public.client_auth_logs OWNER TO wildweasel;

--
-- Name: client_auth_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: wildweasel
--

CREATE SEQUENCE public.client_auth_logs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.client_auth_logs_id_seq OWNER TO wildweasel;

--
-- Name: client_auth_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: wildweasel
--

ALTER SEQUENCE public.client_auth_logs_id_seq OWNED BY public.client_auth_logs.id;


--
-- Name: client_devices; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.client_devices (
    id integer NOT NULL,
    mac character varying NOT NULL,
    total_incoming_packets numeric,
    total_outgoing_packets numeric,
    last_active character varying
);


ALTER TABLE public.client_devices OWNER TO wildweasel;

--
-- Name: client_devices_id_seq; Type: SEQUENCE; Schema: public; Owner: wildweasel
--

CREATE SEQUENCE public.client_devices_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.client_devices_id_seq OWNER TO wildweasel;

--
-- Name: client_devices_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: wildweasel
--

ALTER SEQUENCE public.client_devices_id_seq OWNED BY public.client_devices.id;


--
-- Name: client_list; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.client_list (
    id bigint NOT NULL,
    band character varying(255),
    down character varying(255),
    ip character varying(255),
    macc character varying(255),
    manufacturer character varying(255),
    os character varying(255),
    rssi character varying(255),
    serial_num character varying(255),
    ssid character varying(255),
    traffic character varying(255),
    up character varying(255)
);


ALTER TABLE public.client_list OWNER TO wildweasel;

--
-- Name: client_sessions; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.client_sessions (
    id integer NOT NULL,
    device_id integer NOT NULL,
    package_id integer NOT NULL,
    counter integer,
    created_on timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    date_modified character varying,
    incoming_packets numeric,
    outgoing_packets numeric,
    limit_reached boolean,
    cluster_id integer
);


ALTER TABLE public.client_sessions OWNER TO wildweasel;

--
-- Name: client_sessions_id_seq; Type: SEQUENCE; Schema: public; Owner: wildweasel
--

CREATE SEQUENCE public.client_sessions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.client_sessions_id_seq OWNER TO wildweasel;

--
-- Name: client_sessions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: wildweasel
--

ALTER SEQUENCE public.client_sessions_id_seq OWNED BY public.client_sessions.id;


--
-- Name: client_transactions; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.client_transactions (
    id integer NOT NULL,
    uname character varying,
    gw_sn character varying,
    ip character varying,
    gw_address character varying,
    gw_port character varying,
    device_id integer NOT NULL,
    apmac character varying,
    ssid character varying,
    vlanid character varying,
    token character varying,
    stage character varying,
    package_id integer,
    device character varying,
    date_modified character varying,
    gw_id character varying,
    created_on timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    cluster_id integer
);


ALTER TABLE public.client_transactions OWNER TO wildweasel;

--
-- Name: client_transactions_id_seq; Type: SEQUENCE; Schema: public; Owner: wildweasel
--

CREATE SEQUENCE public.client_transactions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.client_transactions_id_seq OWNER TO wildweasel;

--
-- Name: client_transactions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: wildweasel
--

ALTER SEQUENCE public.client_transactions_id_seq OWNED BY public.client_transactions.id;


--
-- Name: cpe_response_log; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.cpe_response_log (
    id bigint NOT NULL,
    method character varying(255),
    payload character varying(255),
    serial_num character varying(255)
);


ALTER TABLE public.cpe_response_log OWNER TO wildweasel;

--
-- Name: data_limits; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.data_limits (
    id integer NOT NULL,
    modified_by_id integer NOT NULL,
    modified_on character varying,
    value double precision,
    access_type smallint,
    gw_id character varying NOT NULL,
    limit_type character varying(2),
    status smallint,
    created_by_id integer NOT NULL,
    created_on character varying
);


ALTER TABLE public.data_limits OWNER TO wildweasel;

--
-- Name: data_limits_id_seq; Type: SEQUENCE; Schema: public; Owner: wildweasel
--

CREATE SEQUENCE public.data_limits_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.data_limits_id_seq OWNER TO wildweasel;

--
-- Name: data_limits_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: wildweasel
--

ALTER SEQUENCE public.data_limits_id_seq OWNED BY public.data_limits.id;


--
-- Name: device; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.device (
    id bigint NOT NULL,
    activated boolean,
    date_created character varying(255),
    date_modified character varying(255),
    date_offline character varying(255),
    device_name character varying(255),
    device_type character varying(255),
    location character varying(255),
    mac_address character varying(255),
    model character varying(255),
    parent character varying(255),
    second_wan_mac_address character varying(255),
    serial_number character varying(255),
    status character varying(255),
    wan_ip character varying(255)
);


ALTER TABLE public.device OWNER TO wildweasel;

--
-- Name: device_logs; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.device_logs (
    id bigint NOT NULL,
    offtime character varying(255),
    ontime character varying(255),
    reason character varying(255),
    serial_num character varying(255),
    type character varying(255),
    update_time character varying(255)
);


ALTER TABLE public.device_logs OWNER TO wildweasel;

--
-- Name: device_model_parameters; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.device_model_parameters (
    id bigint NOT NULL,
    con_req_url_parameter character varying(255),
    hardware_ver_parameter character varying(255),
    mac_address_parameter character varying(255),
    management_ip_parameter character varying(255),
    manufacturer character varying(255) NOT NULL,
    model character varying(255) NOT NULL,
    public_ip_parameter character varying(255),
    second_wan_mac character varying(255),
    software_ver_parameter character varying(255),
    udp_con_req_url_parameter character varying(255)
);


ALTER TABLE public.device_model_parameters OWNER TO wildweasel;

--
-- Name: device_traffic_24h; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.device_traffic_24h (
    id bigint NOT NULL,
    date character varying(255),
    rx integer,
    serial_num character varying(255),
    "time" character varying(255),
    tx integer
);


ALTER TABLE public.device_traffic_24h OWNER TO wildweasel;

--
-- Name: device_traffic_daily; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.device_traffic_daily (
    id bigint NOT NULL,
    date character varying(255),
    rx integer,
    serial_num character varying(255),
    tx integer
);


ALTER TABLE public.device_traffic_daily OWNER TO wildweasel;

--
-- Name: devices; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.devices (
    id integer NOT NULL,
    mac character varying,
    free_data double precision,
    month_data double precision,
    last_active character varying,
    last_record double precision,
    con_req_url character varying(255),
    cpu_usage character varying(255),
    cwmp_cycle_end boolean,
    device_alias character varying(255),
    hardware_ver character varying(255),
    mac_address character varying(255),
    management_ip character varying(255),
    manufacturer character varying(255),
    memory_usage character varying(255),
    model character varying(255),
    oui character varying(255),
    public_ip character varying(255),
    second_wan_mac character varying(255),
    serial_num character varying(255),
    software_ver character varying(255),
    ssids character varying(255),
    udp_con_req_url character varying(255)
);


ALTER TABLE public.devices OWNER TO wildweasel;

--
-- Name: devices_id_seq; Type: SEQUENCE; Schema: public; Owner: wildweasel
--

CREATE SEQUENCE public.devices_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.devices_id_seq OWNER TO wildweasel;

--
-- Name: devices_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: wildweasel
--

ALTER SEQUENCE public.devices_id_seq OWNED BY public.devices.id;


--
-- Name: gateway_group; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.gateway_group (
    id integer NOT NULL,
    name character varying,
    created_by_id integer NOT NULL,
    created_on character varying,
    modified_by_id integer NOT NULL,
    modified_on character varying,
    status smallint
);


ALTER TABLE public.gateway_group OWNER TO wildweasel;

--
-- Name: gateway_group_id_seq; Type: SEQUENCE; Schema: public; Owner: wildweasel
--

CREATE SEQUENCE public.gateway_group_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.gateway_group_id_seq OWNER TO wildweasel;

--
-- Name: gateway_group_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: wildweasel
--

ALTER SEQUENCE public.gateway_group_id_seq OWNED BY public.gateway_group.id;


--
-- Name: gateway_groups; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.gateway_groups (
    id integer NOT NULL,
    gw_id character varying NOT NULL,
    group_id integer NOT NULL
);


ALTER TABLE public.gateway_groups OWNER TO wildweasel;

--
-- Name: gateway_groups_id_seq; Type: SEQUENCE; Schema: public; Owner: wildweasel
--

CREATE SEQUENCE public.gateway_groups_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.gateway_groups_id_seq OWNER TO wildweasel;

--
-- Name: gateway_groups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: wildweasel
--

ALTER SEQUENCE public.gateway_groups_id_seq OWNED BY public.gateway_groups.id;


--
-- Name: gateways; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.gateways (
    id integer NOT NULL,
    gw_id character varying,
    name character varying,
    modified_on character varying,
    modified_by_id integer NOT NULL,
    status smallint,
    created_by_id integer NOT NULL,
    created_on character varying
);


ALTER TABLE public.gateways OWNER TO wildweasel;

--
-- Name: gateways_id_seq; Type: SEQUENCE; Schema: public; Owner: wildweasel
--

CREATE SEQUENCE public.gateways_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.gateways_id_seq OWNER TO wildweasel;

--
-- Name: gateways_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: wildweasel
--

ALTER SEQUENCE public.gateways_id_seq OWNED BY public.gateways.id;


--
-- Name: group_announcements; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.group_announcements (
    id integer NOT NULL,
    name character varying(64),
    path character varying(128),
    status smallint,
    group_id integer NOT NULL,
    modified_by_id integer NOT NULL,
    modified_on character varying,
    created_by_id integer NOT NULL,
    created_on character varying
);


ALTER TABLE public.group_announcements OWNER TO wildweasel;

--
-- Name: group_announcements_id_seq; Type: SEQUENCE; Schema: public; Owner: wildweasel
--

CREATE SEQUENCE public.group_announcements_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.group_announcements_id_seq OWNER TO wildweasel;

--
-- Name: group_announcements_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: wildweasel
--

ALTER SEQUENCE public.group_announcements_id_seq OWNED BY public.group_announcements.id;


--
-- Name: group_command; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.group_command (
    id bigint NOT NULL,
    command character varying(255),
    description character varying(255),
    model character varying(255),
    parent character varying(255)
);


ALTER TABLE public.group_command OWNER TO wildweasel;

--
-- Name: group_ssid; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.group_ssid (
    id bigint NOT NULL,
    auth boolean,
    downlink integer,
    encryption_mode character varying(255),
    forward_mode character varying(255),
    gateway_id character varying(255),
    limitless boolean,
    parent character varying(255),
    passphrase character varying(255),
    portal_ip character varying(255),
    portal_url character varying(255),
    seamless boolean,
    ssid character varying(255),
    uplink integer,
    vlan_id integer,
    wlan_id integer
);


ALTER TABLE public.group_ssid OWNER TO wildweasel;

--
-- Name: groups; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.groups (
    id bigint NOT NULL,
    child character varying(255),
    date_created character varying(255),
    date_modified character varying(255),
    group_name character varying(255),
    location character varying(255),
    parent character varying(255)
);


ALTER TABLE public.groups OWNER TO wildweasel;

--
-- Name: hibernate_sequence; Type: SEQUENCE; Schema: public; Owner: wildweasel
--

CREATE SEQUENCE public.hibernate_sequence
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.hibernate_sequence OWNER TO wildweasel;

--
-- Name: httprequestlog; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.httprequestlog (
    id bigint NOT NULL,
    cookie character varying(255),
    device_status character varying(255),
    last_request timestamp without time zone,
    serial_num character varying(255)
);


ALTER TABLE public.httprequestlog OWNER TO wildweasel;

--
-- Name: logos; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.logos (
    id integer NOT NULL,
    name character varying(64),
    path character varying(128),
    status smallint,
    gw_id character varying NOT NULL,
    modified_by_id integer NOT NULL,
    modified_on character varying,
    created_by_id integer NOT NULL,
    created_on character varying
);


ALTER TABLE public.logos OWNER TO wildweasel;

--
-- Name: logos_id_seq; Type: SEQUENCE; Schema: public; Owner: wildweasel
--

CREATE SEQUENCE public.logos_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.logos_id_seq OWNER TO wildweasel;

--
-- Name: logos_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: wildweasel
--

ALTER SEQUENCE public.logos_id_seq OWNED BY public.logos.id;


--
-- Name: packages; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.packages (
    id integer NOT NULL,
    title character varying NOT NULL,
    description text,
    limit_count integer,
    limit_type character varying,
    package_type character varying,
    price numeric,
    validity character varying
);


ALTER TABLE public.packages OWNER TO wildweasel;

--
-- Name: packages_id_seq; Type: SEQUENCE; Schema: public; Owner: wildweasel
--

CREATE SEQUENCE public.packages_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.packages_id_seq OWNER TO wildweasel;

--
-- Name: packages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: wildweasel
--

ALTER SEQUENCE public.packages_id_seq OWNED BY public.packages.id;


--
-- Name: radio_info; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.radio_info (
    id bigint NOT NULL,
    band_width character varying(255),
    channel character varying(255),
    gather_time character varying(255),
    power character varying(255),
    radio_index character varying(255),
    sn character varying(255),
    upload_time character varying(255),
    utilization character varying(255)
);


ALTER TABLE public.radio_info OWNER TO wildweasel;

--
-- Name: redirect_links; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.redirect_links (
    id integer NOT NULL,
    gw_id character varying(255),
    url character varying(255) NOT NULL,
    status smallint,
    modified_by_id integer,
    modified_on character varying(255),
    created_by_id integer,
    created_on character varying(255)
);


ALTER TABLE public.redirect_links OWNER TO wildweasel;

--
-- Name: redirect_links_id_seq; Type: SEQUENCE; Schema: public; Owner: wildweasel
--

CREATE SEQUENCE public.redirect_links_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.redirect_links_id_seq OWNER TO wildweasel;

--
-- Name: redirect_links_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: wildweasel
--

ALTER SEQUENCE public.redirect_links_id_seq OWNED BY public.redirect_links.id;


--
-- Name: registered_users; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.registered_users (
    id integer NOT NULL,
    uname character varying,
    registered_data double precision,
    month_data double precision,
    last_active character varying,
    last_record double precision
);


ALTER TABLE public.registered_users OWNER TO wildweasel;

--
-- Name: registered_users_id_seq; Type: SEQUENCE; Schema: public; Owner: wildweasel
--

CREATE SEQUENCE public.registered_users_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.registered_users_id_seq OWNER TO wildweasel;

--
-- Name: registered_users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: wildweasel
--

ALTER SEQUENCE public.registered_users_id_seq OWNED BY public.registered_users.id;


--
-- Name: roles; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.roles (
    id integer NOT NULL,
    role character varying
);


ALTER TABLE public.roles OWNER TO wildweasel;

--
-- Name: roles_id_seq; Type: SEQUENCE; Schema: public; Owner: wildweasel
--

CREATE SEQUENCE public.roles_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.roles_id_seq OWNER TO wildweasel;

--
-- Name: roles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: wildweasel
--

ALTER SEQUENCE public.roles_id_seq OWNED BY public.roles.id;


--
-- Name: session_id_seq; Type: SEQUENCE; Schema: public; Owner: wildweasel
--

CREATE SEQUENCE public.session_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.session_id_seq OWNER TO wildweasel;

--
-- Name: taskhandler; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.taskhandler (
    id bigint NOT NULL,
    method character varying(255),
    optional character varying(255),
    parameters character varying(255),
    serial_num character varying(255)
);


ALTER TABLE public.taskhandler OWNER TO wildweasel;

--
-- Name: webcli_response_log; Type: TABLE; Schema: public; Owner: wildweasel
--

CREATE TABLE public.webcli_response_log (
    id bigint NOT NULL,
    command_output bytea,
    command_used bytea,
    device_sn character varying(255),
    time_saved timestamp without time zone
);


ALTER TABLE public.webcli_response_log OWNER TO wildweasel;

--
-- Name: acc_auth_logs id; Type: DEFAULT; Schema: public; Owner: wildweasel
--

ALTER TABLE ONLY public.acc_auth_logs ALTER COLUMN id SET DEFAULT nextval('public.acc_auth_logs_id_seq'::regclass);


--
-- Name: acc_details id; Type: DEFAULT; Schema: public; Owner: wildweasel
--

ALTER TABLE ONLY public.acc_details ALTER COLUMN id SET DEFAULT nextval('public.acc_details_id_seq'::regclass);


--
-- Name: acc_sessions id; Type: DEFAULT; Schema: public; Owner: wildweasel
--

ALTER TABLE ONLY public.acc_sessions ALTER COLUMN id SET DEFAULT nextval('public.acc_sessions_id_seq'::regclass);


--
-- Name: acc_transactions id; Type: DEFAULT; Schema: public; Owner: wildweasel
--

ALTER TABLE ONLY public.acc_transactions ALTER COLUMN id SET DEFAULT nextval('public.acc_transactions_id_seq'::regclass);


--
-- Name: client_sessions id; Type: DEFAULT; Schema: public; Owner: wildweasel
--

ALTER TABLE ONLY public.client_sessions ALTER COLUMN id SET DEFAULT nextval('public.client_sessions_id_seq'::regclass);


--
-- Data for Name: acc_auth_logs; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.acc_auth_logs (id, "account_Number", mac, gw_id, stage, date) FROM stdin;
2	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-08 09:55:43.624667+00
3	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-08 09:58:51.00577+00
4	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-10 01:58:40.224963+00
5	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-10 02:04:04.360132+00
6	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-10 02:06:54.631566+00
7	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-10 02:19:33.01388+00
8	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-10 02:26:24.330821+00
9	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-10 02:32:49.804434+00
10	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-10 02:44:07.300314+00
11	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-10 02:44:07.300314+00
12	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-10 02:58:38.84012+00
13	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-10 03:04:06.819473+00
14	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-10 03:11:53.82144+00
15	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-10 03:14:08.82417+00
16	admin	ee:e5:0c:d6:c8:c0	mpop9016MP	authenticated	2025-04-10 03:14:08.82417+00
17	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-10 03:29:18.101829+00
18	admin	ee:e5:0c:d6:c8:c0	mpop9016MP	authenticated	2025-04-10 03:29:18.101829+00
19	\N	30:05:05:da:80:c2	mpop9016MP	capture	2025-04-10 03:29:18.101829+00
20	admin	30:05:05:da:80:c2	mpop9016MP	authenticated	2025-04-10 03:29:18.101829+00
21	admin	ee:e5:0c:d6:c8:c0	mpop9016MP	logout	2025-04-10 03:29:18.101829+00
22	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-04-10 03:29:18.101829+00
23	mencer@apollo.com.ph	d8:9e:61:24:76:f3	mpop9016MP	authenticated	2025-04-10 03:29:18.101829+00
24	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-10 03:29:18.101829+00
25	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	authenticated	2025-04-10 03:29:18.101829+00
26	\N	a4:4e:31:88:ad:74	mpop9016MP	capture	2025-04-10 03:29:18.101829+00
27	\N	a4:4e:31:88:ad:74	mpop9016MP	capture	2025-04-10 03:29:18.101829+00
28	\N	d4:f3:2d:3a:7e:ce	mpop9016MP	capture	2025-04-10 03:29:18.101829+00
29	\N	a4:4e:31:88:ad:74	mpop9016MP	capture	2025-04-10 03:29:18.101829+00
30	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	authenticated	2025-04-10 03:29:18.101829+00
31	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	authenticated	2025-04-10 03:29:18.101829+00
32	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	authenticated	2025-04-10 03:29:18.101829+00
33	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	authenticated	2025-04-10 03:29:18.101829+00
34	mencer@apollo.com.ph	d4:f3:2d:3a:7e:ce	mpop9016MP	authenticated	2025-04-10 03:29:18.101829+00
35	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	logout	2025-04-10 03:29:18.101829+00
36	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-10 03:29:18.101829+00
37	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	authenticated	2025-04-10 03:29:18.101829+00
38	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	logout	2025-04-10 03:29:18.101829+00
39	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-10 03:29:18.101829+00
40	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	authenticated	2025-04-10 03:29:18.101829+00
41	\N	8a:87:76:f8:2f:d1	mpop9016MP	logout	2025-04-10 03:29:18.101829+00
42	mencer@apollo.com.ph	d8:9e:61:24:76:f3	mpop9016MP	logout	2025-04-10 03:29:18.101829+00
43	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-04-10 03:29:18.101829+00
44	\N	ca:d0:c1:e0:8d:6e	mpop9016MP	capture	2025-04-10 03:29:18.101829+00
45	mencer@apollo.com.ph	d8:9e:61:24:76:f3	mpop9016MP	authenticated	2025-04-10 03:29:18.101829+00
46	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-10 03:29:18.101829+00
47	ben@apolloglobal.net	ca:d0:c1:e0:8d:6e	mpop9016MP	authenticated	2025-04-10 03:29:18.101829+00
48	ben@apolloglobal.net	ca:d0:c1:e0:8d:6e	mpop9016MP	authenticated	2025-04-10 03:29:18.101829+00
49	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-10 03:29:18.101829+00
50	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-10 03:29:18.101829+00
51	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	authenticated	2025-04-10 03:29:18.101829+00
52	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	logout	2025-04-10 03:29:18.101829+00
53	ben@apolloglobal.net	ca:d0:c1:e0:8d:6e	mpop9016MP	logout	2025-04-10 03:29:18.101829+00
54	mitzi@apolloglobal.net	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-04-10 03:29:18.101829+00
55	mitzi@apolloglobal.net	f4:5c:89:ab:0d:d3	mpop9016MP	logout	2025-04-10 03:29:18.101829+00
56	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-10 03:29:18.101829+00
57	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-10 03:29:18.101829+00
58	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	authenticated	2025-04-10 03:29:18.101829+00
59	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	authenticated	2025-04-10 03:29:18.101829+00
60	mencer@apollo.com.ph	d4:f3:2d:3a:7e:ce	mpop9016MP	logout	2025-04-10 03:29:18.101829+00
61	admin	30:05:05:da:80:c2	mpop9016MP	logout	2025-04-10 03:29:18.101829+00
62	\N	d4:f3:2d:3a:7e:ce	mpop9016MP	capture	2025-04-10 03:29:18.101829+00
63	mencer@apollo.com.ph	d4:f3:2d:3a:7e:ce	mpop9016MP	authenticated	2025-04-10 03:29:18.101829+00
64	\N	30:05:05:da:80:c2	mpop9016MP	capture	2025-04-10 03:29:18.101829+00
65	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	authenticated	2025-04-10 03:29:18.101829+00
66	\N	ca:d0:c1:e0:8d:6e	mpop9016MP	capture	2025-04-10 06:54:57.017288+00
67	ben@apolloglobal.net	ca:d0:c1:e0:8d:6e	mpop9016MP	authenticated	2025-04-10 06:54:57.017288+00
68	ben@apolloglobal.net	ca:d0:c1:e0:8d:6e	mpop9016MP	logout	2025-04-10 06:54:57.017288+00
69	mencer@apollo.com.ph	d4:f3:2d:3a:7e:ce	mpop9016MP	logout	2025-04-10 06:54:57.017288+00
70	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	logout	2025-04-10 06:54:57.017288+00
71	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	logout	2025-04-10 06:54:57.017288+00
72	\N	d4:f3:2d:3a:7e:ce	mpop9016MP	capture	2025-04-10 06:54:57.017288+00
73	\N	ca:d0:c1:e0:8d:6e	mpop9016MP	capture	2025-04-10 06:54:57.017288+00
74	mencer@apollo.com.ph	d4:f3:2d:3a:7e:ce	mpop9016MP	authenticated	2025-04-10 06:54:57.017288+00
75	\N	ca:d0:c1:e0:8d:6e	mpop9016MP	capture	2025-04-10 06:54:57.017288+00
76	ben@apolloglobal.net	ca:d0:c1:e0:8d:6e	mpop9016MP	authenticated	2025-04-10 06:54:57.017288+00
77	\N	80:91:33:7a:84:1f	mpop9016MP	capture	2025-04-10 06:54:57.017288+00
78	charchel@apollo.com.ph	80:91:33:7a:84:1f	mpop9016MP	authenticated	2025-04-10 06:54:57.017288+00
79	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-10 06:54:57.017288+00
80	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-10 06:54:57.017288+00
81	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	authenticated	2025-04-10 06:54:57.017288+00
82	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	logout	2025-04-10 06:54:57.017288+00
83	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-10 08:59:42.343093+00
84	admin	ee:e5:0c:d6:c8:c0	mpop9016MP	authenticated	2025-04-10 08:59:42.343093+00
85	admin	ee:e5:0c:d6:c8:c0	mpop9016MP	logout	2025-04-10 08:59:42.343093+00
86	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-10 08:59:42.343093+00
87	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	authenticated	2025-04-10 08:59:42.343093+00
88	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	authenticated	2025-04-10 08:59:42.343093+00
89	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-10 08:59:42.343093+00
90	mencer@apollo.com.ph	d4:f3:2d:3a:7e:ce	mpop9016MP	logout	2025-04-10 08:59:42.343093+00
91	mencer@apollo.com.ph	d8:9e:61:24:76:f3	mpop9016MP	logout	2025-04-10 08:59:42.343093+00
92	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	logout	2025-04-10 08:59:42.343093+00
93	charchel@apollo.com.ph	80:91:33:7a:84:1f	mpop9016MP	logout	2025-04-10 08:59:42.343093+00
94	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-11 01:07:04.650518+00
95	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-11 01:07:04.650518+00
96	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	authenticated	2025-04-11 01:07:04.650518+00
97	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-11 01:07:04.650518+00
98	mitzi@apolloglobal.net	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-04-11 01:07:04.650518+00
99	\N	30:05:05:da:80:c2	mpop9016MP	capture	2025-04-11 01:07:04.650518+00
100	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	authenticated	2025-04-11 01:07:04.650518+00
101	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-11 01:07:04.650518+00
102	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	logout	2025-04-11 01:07:04.650518+00
103	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-04-11 01:07:04.650518+00
104	\N	a2:a4:ab:81:45:1e	mpop9016MP	capture	2025-04-11 01:07:04.650518+00
105	mencer@apollo.com.ph	d8:9e:61:24:76:f3	mpop9016MP	authenticated	2025-04-11 01:07:04.650518+00
106	charchel@apollo.com.ph	a2:a4:ab:81:45:1e	mpop9016MP	authenticated	2025-04-11 01:07:04.650518+00
107	\N	30:05:05:da:80:c2	mpop9016MP	capture	2025-04-11 01:07:04.650518+00
108	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	authenticated	2025-04-11 01:07:04.650518+00
109	\N	d4:f3:2d:3a:7e:ce	mpop9016MP	capture	2025-04-11 01:07:04.650518+00
110	mencer@apollo.com.ph	d4:f3:2d:3a:7e:ce	mpop9016MP	authenticated	2025-04-11 01:07:04.650518+00
111	\N	80:91:33:7a:84:1f	mpop9016MP	capture	2025-04-11 01:07:04.650518+00
112	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	logout	2025-04-11 01:07:04.650518+00
113	\N	a4:4e:31:88:ad:74	mpop9016MP	capture	2025-04-11 01:07:04.650518+00
114	\N	a4:4e:31:88:ad:74	mpop9016MP	capture	2025-04-11 01:07:04.650518+00
115	charchel@apollo.com.ph	80:91:33:7a:84:1f	mpop9016MP	authenticated	2025-04-11 01:07:04.650518+00
116	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	authenticated	2025-04-11 01:07:04.650518+00
117	\N	30:05:05:da:80:c2	mpop9016MP	capture	2025-04-11 01:38:15.719847+00
118	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	authenticated	2025-04-11 01:38:15.719847+00
119	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-11 01:38:15.719847+00
120	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 01:38:15.719847+00
121	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	authenticated	2025-04-11 01:38:15.719847+00
122	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	authenticated	2025-04-11 01:38:15.719847+00
123	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	logout	2025-04-11 02:23:34.443085+00
124	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
125	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	authenticated	2025-04-11 02:23:34.443085+00
126	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	logout	2025-04-11 02:23:34.443085+00
127	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	logout	2025-04-11 02:23:34.443085+00
128	\N	30:05:05:da:80:c2	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
129	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	authenticated	2025-04-11 02:23:34.443085+00
130	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
131	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	authenticated	2025-04-11 02:23:34.443085+00
132	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
133	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	authenticated	2025-04-11 02:23:34.443085+00
134	charchel@apollo.com.ph	a2:a4:ab:81:45:1e	mpop9016MP	logout	2025-04-11 02:23:34.443085+00
135	mitzi@apolloglobal.net	f4:5c:89:ab:0d:d3	mpop9016MP	logout	2025-04-11 02:23:34.443085+00
136	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	logout	2025-04-11 02:23:34.443085+00
137	charchel@apollo.com.ph	80:91:33:7a:84:1f	mpop9016MP	logout	2025-04-11 02:23:34.443085+00
138	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
139	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	authenticated	2025-04-11 02:23:34.443085+00
140	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
141	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	logout	2025-04-11 02:23:34.443085+00
142	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	logout	2025-04-11 02:23:34.443085+00
143	mitzi@apolloglobal.net	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-04-11 02:23:34.443085+00
144	\N	30:05:05:da:80:c2	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
145	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	authenticated	2025-04-11 02:23:34.443085+00
146	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	logout	2025-04-11 02:23:34.443085+00
147	mencer@apollo.com.ph	d8:9e:61:24:76:f3	mpop9016MP	logout	2025-04-11 02:23:34.443085+00
148	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
149	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	authenticated	2025-04-11 02:23:34.443085+00
150	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
151	\N	80:91:33:7a:84:1f	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
152	charchel@apollo.com.ph	80:91:33:7a:84:1f	mpop9016MP	authenticated	2025-04-11 02:23:34.443085+00
153	mencer@apollo.com.ph	d8:9e:61:24:76:f3	mpop9016MP	authenticated	2025-04-11 02:23:34.443085+00
154	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
155	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	authenticated	2025-04-11 02:23:34.443085+00
156	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	logout	2025-04-11 02:23:34.443085+00
157	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	logout	2025-04-11 02:23:34.443085+00
158	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	logout	2025-04-11 02:23:34.443085+00
159	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
160	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	authenticated	2025-04-11 02:23:34.443085+00
161	\N	a4:4e:31:88:ad:74	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
162	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	authenticated	2025-04-11 02:23:34.443085+00
163	\N	66:c3:c1:58:21:64	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
164	mencer@apollo.com.ph	d4:f3:2d:3a:7e:ce	mpop9016MP	logout	2025-04-11 02:23:34.443085+00
165	\N	d4:f3:2d:3a:7e:ce	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
166	mencer@apollo.com.ph	d4:f3:2d:3a:7e:ce	mpop9016MP	authenticated	2025-04-11 02:23:34.443085+00
167	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
168	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	authenticated	2025-04-11 02:23:34.443085+00
169	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	logout	2025-04-11 02:23:34.443085+00
170	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	logout	2025-04-11 02:23:34.443085+00
171	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	logout	2025-04-11 02:23:34.443085+00
172	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
173	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	authenticated	2025-04-11 02:23:34.443085+00
174	\N	a4:4e:31:88:ad:74	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
175	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	authenticated	2025-04-11 02:23:34.443085+00
176	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	logout	2025-04-11 02:23:34.443085+00
177	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
178	mencer@apollo.com.ph	d4:f3:2d:3a:7e:ce	mpop9016MP	logout	2025-04-11 02:23:34.443085+00
179	mencer@apollo.com.ph	d8:9e:61:24:76:f3	mpop9016MP	logout	2025-04-11 02:23:34.443085+00
180	\N	d4:f3:2d:3a:7e:ce	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
181	mencer@apollo.com.ph	d4:f3:2d:3a:7e:ce	mpop9016MP	authenticated	2025-04-11 02:23:34.443085+00
182	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
183	mencer@apollo.com.ph	d8:9e:61:24:76:f3	mpop9016MP	authenticated	2025-04-11 02:23:34.443085+00
184	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	logout	2025-04-11 02:23:34.443085+00
185	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
186	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
187	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
188	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
189	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
190	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
191	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
192	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
193	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
194	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
195	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
196	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
197	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
198	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
199	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
200	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
201	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	authenticated	2025-04-11 02:23:34.443085+00
202	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	authenticated	2025-04-11 02:23:34.443085+00
203	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
204	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	authenticated	2025-04-11 02:23:34.443085+00
205	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	logout	2025-04-11 02:23:34.443085+00
206	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
207	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	authenticated	2025-04-11 02:23:34.443085+00
208	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
209	\N	ca:d0:c1:e0:8d:6e	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
210	ben@apolloglobal.net	ca:d0:c1:e0:8d:6e	mpop9016MP	authenticated	2025-04-11 02:23:34.443085+00
211	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
212	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
213	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
214	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
215	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
216	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
217	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
218	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
219	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
220	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
221	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
222	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
223	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
224	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
225	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
226	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
227	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
228	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
229	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
230	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
231	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
232	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
233	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
234	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
235	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
236	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	logout	2025-04-11 02:23:34.443085+00
237	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
238	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
239	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
240	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
241	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
242	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-11 02:23:34.443085+00
243	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
244	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	authenticated	2025-04-14 01:09:51.213168+00
245	\N	30:05:05:da:80:c2	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
246	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	authenticated	2025-04-14 01:09:51.213168+00
247	\N	d4:f3:2d:3a:7e:ce	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
248	mencer@apollo.com.ph	d4:f3:2d:3a:7e:ce	mpop9016MP	authenticated	2025-04-14 01:09:51.213168+00
249	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
250	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	authenticated	2025-04-14 01:09:51.213168+00
251	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
252	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	authenticated	2025-04-14 01:09:51.213168+00
253	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	logout	2025-04-14 01:09:51.213168+00
254	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
255	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	authenticated	2025-04-14 01:09:51.213168+00
256	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
257	mitzi@apolloglobal.net	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-04-14 01:09:51.213168+00
258	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	logout	2025-04-14 01:09:51.213168+00
259	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
260	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
261	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
262	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
263	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
264	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
265	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
266	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
267	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
268	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
272	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
273	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	authenticated	2025-04-14 01:09:51.213168+00
276	\N	a4:4e:31:88:ad:74	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
277	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	authenticated	2025-04-14 01:09:51.213168+00
279	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	authenticated	2025-04-14 01:09:51.213168+00
280	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	logout	2025-04-14 01:09:51.213168+00
281	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
282	\N	a4:4e:31:88:ad:74	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
283	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	authenticated	2025-04-14 01:09:51.213168+00
285	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
289	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
290	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
294	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
300	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
302	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
305	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
308	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
310	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
312	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
314	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
269	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
270	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
271	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	authenticated	2025-04-14 01:09:51.213168+00
274	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
275	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	authenticated	2025-04-14 01:09:51.213168+00
278	\N	30:05:05:da:80:c2	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
284	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
286	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
287	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
288	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
291	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
292	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
293	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
295	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
296	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
297	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
298	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
299	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
301	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
303	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
304	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
306	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
307	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
309	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
311	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
313	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
315	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
316	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
317	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
318	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
319	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
320	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
321	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
322	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
323	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
324	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
325	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
326	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
327	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
328	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
329	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
330	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
331	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
332	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
333	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
334	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
335	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
336	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
337	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
338	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
339	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
340	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
341	mitzi@apolloglobal.net	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-04-14 01:09:51.213168+00
342	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
343	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
344	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
345	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
346	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
347	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
348	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
349	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
350	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
351	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
352	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
353	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
354	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
355	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
356	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
357	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
358	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
359	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
360	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
361	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
362	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
363	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
364	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
365	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
366	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
367	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
368	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
369	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
370	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
371	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
372	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
373	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
374	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
375	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
376	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
377	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
378	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
379	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
380	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
381	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
382	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
383	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
384	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
385	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	authenticated	2025-04-14 01:09:51.213168+00
387	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
390	\N	ca:d0:c1:e0:8d:6e	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
394	\N	ca:d0:c1:e0:8d:6e	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
395	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
398	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
404	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
405	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
386	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	logout	2025-04-14 01:09:51.213168+00
388	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	authenticated	2025-04-14 01:09:51.213168+00
389	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
391	\N	ca:d0:c1:e0:8d:6e	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
392	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	logout	2025-04-14 01:09:51.213168+00
393	\N	ca:d0:c1:e0:8d:6e	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
396	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
397	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
399	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
400	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
401	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
402	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	logout	2025-04-14 01:09:51.213168+00
403	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
406	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
407	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	authenticated	2025-04-14 01:09:51.213168+00
408	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-14 01:09:51.213168+00
409	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	logout	2025-04-14 01:09:51.213168+00
410	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
411	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	authenticated	2025-04-14 09:15:24.166192+00
412	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
413	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	authenticated	2025-04-14 09:15:24.166192+00
414	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	authenticated	2025-04-14 09:15:24.166192+00
415	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
416	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
417	mitzi@apolloglobal.net	f4:5c:89:ab:0d:d3	mpop9016MP	logout	2025-04-14 09:15:24.166192+00
418	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
419	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	logout	2025-04-14 09:15:24.166192+00
420	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	logout	2025-04-14 09:15:24.166192+00
421	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	logout	2025-04-14 09:15:24.166192+00
422	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	logout	2025-04-14 09:15:24.166192+00
423	\N	5a:82:9d:bb:95:a0	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
424	\N	a4:4e:31:88:ad:74	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
425	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	authenticated	2025-04-14 09:15:24.166192+00
426	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
427	mencer@apollo.com.ph	d8:9e:61:24:76:f3	mpop9016MP	authenticated	2025-04-14 09:15:24.166192+00
428	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
429	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
430	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	authenticated	2025-04-14 09:15:24.166192+00
431	mencer@apollo.com.ph	d8:9e:61:24:76:f3	mpop9016MP	logout	2025-04-14 09:15:24.166192+00
432	\N	ca:d0:c1:e0:8d:6e	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
433	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
434	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	authenticated	2025-04-14 09:15:24.166192+00
435	\N	30:05:05:da:80:c2	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
436	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	authenticated	2025-04-14 09:15:24.166192+00
437	\N	ca:d0:c1:e0:8d:6e	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
438	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
439	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	authenticated	2025-04-14 09:15:24.166192+00
440	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	logout	2025-04-14 09:15:24.166192+00
441	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
442	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	authenticated	2025-04-14 09:15:24.166192+00
443	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	logout	2025-04-14 09:15:24.166192+00
444	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
445	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	authenticated	2025-04-14 09:15:24.166192+00
446	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	logout	2025-04-14 09:15:24.166192+00
447	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
448	admin	ee:e5:0c:d6:c8:c0	mpop9016MP	authenticated	2025-04-14 09:15:24.166192+00
449	admin	ee:e5:0c:d6:c8:c0	mpop9016MP	logout	2025-04-14 09:15:24.166192+00
450	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
451	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
452	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	authenticated	2025-04-14 09:15:24.166192+00
453	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
454	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
455	mencer@apollo.com.ph	d8:9e:61:24:76:f3	mpop9016MP	authenticated	2025-04-14 09:15:24.166192+00
456	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
457	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
458	mitzi@apolloglobal.net	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-04-14 09:15:24.166192+00
459	mitzi@apolloglobal.net	f4:5c:89:ab:0d:d3	mpop9016MP	logout	2025-04-14 09:15:24.166192+00
460	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	logout	2025-04-14 09:15:24.166192+00
461	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	logout	2025-04-14 09:15:24.166192+00
462	\N	a4:4e:31:88:ad:74	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
463	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	authenticated	2025-04-14 09:15:24.166192+00
464	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
465	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	authenticated	2025-04-14 09:15:24.166192+00
466	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	logout	2025-04-14 09:15:24.166192+00
467	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	logout	2025-04-14 09:15:24.166192+00
468	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
469	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	logout	2025-04-14 09:15:24.166192+00
470	\N	30:05:05:da:80:c2	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
471	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
472	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	authenticated	2025-04-14 09:15:24.166192+00
473	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
474	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	authenticated	2025-04-14 09:15:24.166192+00
475	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
476	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
477	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-14 09:15:24.166192+00
478	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-15 06:12:27.967388+00
479	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	logout	2025-04-15 06:28:42.191392+00
480	\N	d8:9e:61:24:76:f3	mpop9016MP	logout	2025-04-15 06:28:42.191392+00
481	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-15 06:28:42.191392+00
482	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-15 06:28:42.191392+00
483	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-15 06:28:42.191392+00
484	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-15 06:28:42.191392+00
485	\N	a4:4e:31:88:ad:74	mpop9016MP	capture	2025-04-15 06:28:42.191392+00
486	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	authenticated	2025-04-15 06:28:42.191392+00
487	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-15 06:28:42.191392+00
488	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	authenticated	2025-04-15 06:28:42.191392+00
489	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-15 06:28:42.191392+00
490	\N	30:05:05:da:80:c2	mpop9016MP	capture	2025-04-15 06:28:42.191392+00
491	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	authenticated	2025-04-15 06:28:42.191392+00
492	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-15 06:28:42.191392+00
493	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	authenticated	2025-04-15 06:28:42.191392+00
494	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-15 06:28:42.191392+00
495	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-16 01:25:03.439853+00
496	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	logout	2025-04-16 01:25:03.439853+00
497	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-16 01:25:03.439853+00
498	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	authenticated	2025-04-16 01:25:03.439853+00
499	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-16 01:27:08.472765+00
500	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-16 01:27:08.472765+00
501	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-16 01:27:08.472765+00
502	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-16 01:27:08.472765+00
503	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-16 01:27:08.472765+00
504	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-16 01:27:08.472765+00
505	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-16 01:27:08.472765+00
506	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-16 05:11:59.086748+00
507	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-16 05:23:12.102365+00
508	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-16 05:23:12.102365+00
509	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-16 05:26:48.17189+00
510	RES-201901-16	72:80:ea:58:b0:00	mpop9016MP	authenticated	2025-04-16 05:26:48.17189+00
511	RES-201901-16	72:80:ea:58:b0:00	mpop9016MP	logout	2025-04-16 05:26:48.17189+00
512	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-16 05:26:48.17189+00
513	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-16 05:49:40.996834+00
514	RES-201901-16	72:80:ea:58:b0:00	mpop9016MP	authenticated	2025-04-16 05:49:40.996834+00
515	RES-201901-16	72:80:ea:58:b0:00	mpop9016MP	logout	2025-04-16 05:49:40.996834+00
516	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-16 05:49:40.996834+00
517	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-16 05:49:40.996834+00
518	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
519	RES-201901-16	72:80:ea:58:b0:00	mpop9016MP	authenticated	2025-04-16 06:07:38.26412+00
520	RES-201901-16	72:80:ea:58:b0:00	mpop9016MP	logout	2025-04-16 06:07:38.26412+00
521	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
522	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
523	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
524	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
525	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
526	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
527	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
528	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
529	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
530	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
531	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
532	\N	ca:d0:c1:e0:8d:6e	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
533	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	logout	2025-04-16 06:07:38.26412+00
534	annanicole@apollo.com.ph	ee:e5:0c:d6:c8:c0	mpop9016MP	logout	2025-04-16 06:07:38.26412+00
535	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	logout	2025-04-16 06:07:38.26412+00
536	\N	16:07:dd:3c:fa:c3	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
537	\N	d4:a3:65:3b:01:46	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
538	\N	d4:a3:65:3b:01:46	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
539	\N	d4:a3:65:3b:01:46	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
540	\N	d4:a3:65:3b:01:46	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
541	\N	d4:a3:65:3b:01:46	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
542	\N	2e:19:fc:b9:8b:96	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
543	\N	2e:19:fc:b9:8b:96	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
544	\N	2e:19:fc:b9:8b:96	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
545	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
546	\N	a4:4e:31:88:ad:74	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
547	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
548	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
549	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-16 06:07:38.26412+00
550	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
551	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
552	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	authenticated	2025-04-21 00:56:31.881964+00
553	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
554	\N	30:05:05:da:80:c2	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
555	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	authenticated	2025-04-21 00:56:31.881964+00
556	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	logout	2025-04-21 00:56:31.881964+00
557	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
558	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
559	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
560	\N	30:05:05:da:80:c2	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
561	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
562	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
563	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
564	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	authenticated	2025-04-21 00:56:31.881964+00
565	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	logout	2025-04-21 00:56:31.881964+00
566	\N	30:05:05:da:80:c2	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
567	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	authenticated	2025-04-21 00:56:31.881964+00
568	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
569	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
570	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
571	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	logout	2025-04-21 00:56:31.881964+00
572	\N	30:05:05:da:80:c2	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
573	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	logout	2025-04-21 00:56:31.881964+00
574	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
575	\N	a4:4e:31:88:ad:74	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
576	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	authenticated	2025-04-21 00:56:31.881964+00
577	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
578	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	authenticated	2025-04-21 00:56:31.881964+00
579	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
580	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
581	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	authenticated	2025-04-21 00:56:31.881964+00
582	\N	12:dc:6f:d5:5d:4f	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
583	apollo	12:dc:6f:d5:5d:4f	mpop9016MP	authenticated	2025-04-21 00:56:31.881964+00
584	\N	1e:f4:0c:75:67:af	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
585	apollo	1e:f4:0c:75:67:af	mpop9016MP	authenticated	2025-04-21 00:56:31.881964+00
586	apollo	12:dc:6f:d5:5d:4f	mpop9016MP	logout	2025-04-21 00:56:31.881964+00
587	apollo	1e:f4:0c:75:67:af	mpop9016MP	logout	2025-04-21 00:56:31.881964+00
588	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	logout	2025-04-21 00:56:31.881964+00
589	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	logout	2025-04-21 00:56:31.881964+00
590	\N	a4:4e:31:88:ad:74	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
591	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	authenticated	2025-04-21 00:56:31.881964+00
592	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
593	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	authenticated	2025-04-21 00:56:31.881964+00
594	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
595	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	authenticated	2025-04-21 00:56:31.881964+00
596	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	logout	2025-04-21 00:56:31.881964+00
597	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
598	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	authenticated	2025-04-21 00:56:31.881964+00
599	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	logout	2025-04-21 00:56:31.881964+00
600	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
601	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
602	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
603	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
604	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
605	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
606	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
607	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
608	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
609	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
610	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
611	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	authenticated	2025-04-21 00:56:31.881964+00
612	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	logout	2025-04-21 00:56:31.881964+00
613	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
614	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
615	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
616	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
617	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
618	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
619	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
620	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	authenticated	2025-04-21 00:56:31.881964+00
621	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	logout	2025-04-21 00:56:31.881964+00
622	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
623	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
624	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
625	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
626	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
627	\N	6e:1d:a6:56:29:24	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
628	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
629	admin	72:80:ea:58:b0:00	mpop9016MP	authenticated	2025-04-21 00:56:31.881964+00
630	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
631	\N	72:80:ea:58:b0:00	mpop9016MP	logout	2025-04-21 00:56:31.881964+00
632	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	logout	2025-04-21 00:56:31.881964+00
633	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
634	admin	72:80:ea:58:b0:00	mpop9016MP	authenticated	2025-04-21 00:56:31.881964+00
635	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
636	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
637	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	logout	2025-04-21 00:56:31.881964+00
638	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	logout	2025-04-21 00:56:31.881964+00
639	admin	72:80:ea:58:b0:00	mpop9016MP	logout	2025-04-21 00:56:31.881964+00
640	\N	2e:19:fc:b9:8b:96	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
641	\N	2e:19:fc:b9:8b:96	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
642	\N	2e:19:fc:b9:8b:96	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
643	\N	2e:19:fc:b9:8b:96	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
644	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
645	\N	a4:4e:31:88:ad:74	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
646	\N	a4:4e:31:88:ad:74	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
647	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	authenticated	2025-04-21 00:56:31.881964+00
648	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
649	admin	72:80:ea:58:b0:00	mpop9016MP	authenticated	2025-04-21 00:56:31.881964+00
650	\N	6e:1d:a6:56:29:24	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
651	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
652	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
653	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	authenticated	2025-04-21 00:56:31.881964+00
654	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
655	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
656	mencer@apollo.com.ph	d8:9e:61:24:76:f3	mpop9016MP	authenticated	2025-04-21 00:56:31.881964+00
657	\N	4a:2b:46:c3:61:3e	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
658	\N	9a:9f:b3:0c:d5:0c	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
659	\N	6e:1d:a6:56:29:24	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
660	\N	6e:1d:a6:56:29:24	mpop9016MP	capture	2025-04-21 00:56:31.881964+00
661	\N	6e:1d:a6:56:29:24	mpop9016MP	capture	2025-04-23 01:10:48.881722+00
662	admin	72:80:ea:58:b0:00	mpop9016MP	logout	2025-04-23 01:10:48.881722+00
663	\N	6e:1d:a6:56:29:24	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
664	\N	6e:1d:a6:56:29:24	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
665	RES-201901-16	6e:1d:a6:56:29:24	mpop9016MP	authenticated	2025-04-23 01:13:00.408398+00
666	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
667	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
668	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	authenticated	2025-04-23 01:13:00.408398+00
669	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	logout	2025-04-23 01:13:00.408398+00
670	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	logout	2025-04-23 01:13:00.408398+00
671	RES-201901-16	6e:1d:a6:56:29:24	mpop9016MP	logout	2025-04-23 01:13:00.408398+00
672	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	logout	2025-04-23 01:13:00.408398+00
673	\N	a4:4e:31:88:ad:74	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
674	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	authenticated	2025-04-23 01:13:00.408398+00
675	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
676	admin	72:80:ea:58:b0:00	mpop9016MP	authenticated	2025-04-23 01:13:00.408398+00
677	mencer@apollo.com.ph	d8:9e:61:24:76:f3	mpop9016MP	logout	2025-04-23 01:13:00.408398+00
678	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
679	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	authenticated	2025-04-23 01:13:00.408398+00
680	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
681	mencer@apollo.com.ph	d8:9e:61:24:76:f3	mpop9016MP	authenticated	2025-04-23 01:13:00.408398+00
682	mencer@apollo.com.ph	d8:9e:61:24:76:f3	mpop9016MP	logout	2025-04-23 01:13:00.408398+00
683	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	logout	2025-04-23 01:13:00.408398+00
684	\N	a4:4e:31:88:ad:74	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
685	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	authenticated	2025-04-23 01:13:00.408398+00
686	\N	46:b9:52:2b:e7:cb	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
687	RES-201901-16	46:b9:52:2b:e7:cb	mpop9016MP	authenticated	2025-04-23 01:13:00.408398+00
688	RES-201901-16	46:b9:52:2b:e7:cb	mpop9016MP	logout	2025-04-23 01:13:00.408398+00
689	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	logout	2025-04-23 01:13:00.408398+00
690	\N	ca:d0:c1:e0:8d:6e	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
691	ben@apolloglobal.net	ca:d0:c1:e0:8d:6e	mpop9016MP	authenticated	2025-04-23 01:13:00.408398+00
692	admin	72:80:ea:58:b0:00	mpop9016MP	logout	2025-04-23 01:13:00.408398+00
693	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
694	ben@apolloglobal.net	ca:d0:c1:e0:8d:6e	mpop9016MP	logout	2025-04-23 01:13:00.408398+00
695	\N	ca:d0:c1:e0:8d:6e	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
696	\N	6e:1d:a6:56:29:24	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
697	RES-201901-16	6e:1d:a6:56:29:24	mpop9016MP	authenticated	2025-04-23 01:13:00.408398+00
698	\N	ca:d0:c1:e0:8d:6e	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
699	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	logout	2025-04-23 01:13:00.408398+00
700	\N	9a:9f:b3:0c:d5:0c	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
701	RES-201901-16	9a:9f:b3:0c:d5:0c	mpop9016MP	authenticated	2025-04-23 01:13:00.408398+00
702	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
703	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
704	RES-201901-16	9a:9f:b3:0c:d5:0c	mpop9016MP	logout	2025-04-23 01:13:00.408398+00
705	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
706	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
707	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
708	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
709	mitzi@apolloglobal.net	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-04-23 01:13:00.408398+00
710	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
711	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	authenticated	2025-04-23 01:13:00.408398+00
712	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	logout	2025-04-23 01:13:00.408398+00
713	\N	a4:4e:31:88:ad:74	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
714	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	authenticated	2025-04-23 01:13:00.408398+00
715	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
716	mencer@apollo.com.ph	d8:9e:61:24:76:f3	mpop9016MP	authenticated	2025-04-23 01:13:00.408398+00
717	\N	30:05:05:da:80:c2	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
718	annanicole@apollo.com.ph	30:05:05:da:80:c2	mpop9016MP	authenticated	2025-04-23 01:13:00.408398+00
719	mencer@apollo.com.ph	d8:9e:61:24:76:f3	mpop9016MP	logout	2025-04-23 01:13:00.408398+00
720	\N	6e:1d:a6:56:29:24	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
721	RES-201901-16	6e:1d:a6:56:29:24	mpop9016MP	authenticated	2025-04-23 01:13:00.408398+00
722	RES-201901-16	6e:1d:a6:56:29:24	mpop9016MP	logout	2025-04-23 01:13:00.408398+00
723	\N	6e:1d:a6:56:29:24	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
724	\N	6e:1d:a6:56:29:24	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
725	RES-201901-16	6e:1d:a6:56:29:24	mpop9016MP	authenticated	2025-04-23 01:13:00.408398+00
726	RES-201901-16	6e:1d:a6:56:29:24	mpop9016MP	logout	2025-04-23 01:13:00.408398+00
727	\N	6e:1d:a6:56:29:24	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
728	RES-201901-16	6e:1d:a6:56:29:24	mpop9016MP	authenticated	2025-04-23 01:13:00.408398+00
729	RES-201901-16	6e:1d:a6:56:29:24	mpop9016MP	logout	2025-04-23 01:13:00.408398+00
730	\N	6e:1d:a6:56:29:24	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
731	\N	6e:1d:a6:56:29:24	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
732	RES-201901-16	6e:1d:a6:56:29:24	mpop9016MP	authenticated	2025-04-23 01:13:00.408398+00
733	RES-201901-16	6e:1d:a6:56:29:24	mpop9016MP	logout	2025-04-23 01:13:00.408398+00
734	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	logout	2025-04-23 01:13:00.408398+00
735	\N	a4:4e:31:88:ad:74	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
736	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	authenticated	2025-04-23 01:13:00.408398+00
737	\N	46:b9:52:2b:e7:cb	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
738	\N	46:b9:52:2b:e7:cb	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
739	\N	46:b9:52:2b:e7:cb	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
740	\N	9a:9f:b3:0c:d5:0c	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
741	RES-201901-16	9a:9f:b3:0c:d5:0c	mpop9016MP	authenticated	2025-04-23 01:13:00.408398+00
742	RES-201901-16	9a:9f:b3:0c:d5:0c	mpop9016MP	logout	2025-04-23 01:13:00.408398+00
743	\N	9a:9f:b3:0c:d5:0c	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
744	\N	9a:9f:b3:0c:d5:0c	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
745	RES-201901-16	9a:9f:b3:0c:d5:0c	mpop9016MP	authenticated	2025-04-23 01:13:00.408398+00
746	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
747	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
748	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
749	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	authenticated	2025-04-23 01:13:00.408398+00
750	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
751	RES-201901-16	9a:9f:b3:0c:d5:0c	mpop9016MP	logout	2025-04-23 01:13:00.408398+00
755	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
752	\N	f0:9e:4a:1e:dc:19	mpop9016MP	logout	2025-04-23 01:13:00.408398+00
765	\N	f0:9e:4a:1e:dc:19	mpop9016MP	logout	2025-04-23 01:13:00.408398+00
766	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
753	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
754	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	authenticated	2025-04-23 01:13:00.408398+00
756	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
757	\N	1a:c0:ed:de:e7:c8	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
758	\N	1a:c0:ed:de:e7:c8	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
759	\N	1a:c0:ed:de:e7:c8	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
760	\N	f6:1c:7d:ae:91:d0	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
761	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
762	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
763	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
764	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
767	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-23 01:13:00.408398+00
768	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-24 06:02:25.471348+00
769	\N	9a:9f:b3:0c:d5:0c	mpop9016MP	capture	2025-04-24 06:02:25.471348+00
770	\N	1a:c0:ed:de:e7:c8	mpop9016MP	capture	2025-04-24 06:02:25.471348+00
771	RES-201901-16	1a:c0:ed:de:e7:c8	mpop9016MP	authenticated	2025-04-24 06:02:25.471348+00
772	\N	46:b9:52:2b:e7:cb	mpop9016MP	capture	2025-04-24 06:02:25.471348+00
773	\N	46:b9:52:2b:e7:cb	mpop9016MP	capture	2025-04-24 06:02:25.471348+00
774	RES-201901-16	46:b9:52:2b:e7:cb	mpop9016MP	authenticated	2025-04-24 06:02:25.471348+00
775	\N	6e:1d:a6:56:29:24	mpop9016MP	capture	2025-04-24 06:02:25.471348+00
776	RES-201901-16	6e:1d:a6:56:29:24	mpop9016MP	authenticated	2025-04-24 06:02:25.471348+00
777	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-24 06:02:25.471348+00
778	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	authenticated	2025-04-24 06:02:25.471348+00
779	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-24 06:02:25.471348+00
780	RES-201901-16	6e:1d:a6:56:29:24	mpop9016MP	logout	2025-04-24 06:02:25.471348+00
781	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	logout	2025-04-24 06:02:25.471348+00
782	RES-201901-16	1a:c0:ed:de:e7:c8	mpop9016MP	logout	2025-04-24 06:02:25.471348+00
783	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-24 06:02:25.471348+00
784	RES-201901-16	46:b9:52:2b:e7:cb	mpop9016MP	logout	2025-04-24 06:02:25.471348+00
785	\N	46:b9:52:2b:e7:cb	mpop9016MP	capture	2025-04-24 06:02:25.471348+00
786	\N	12:dc:6f:d5:5d:4f	mpop9016MP	capture	2025-04-24 06:02:25.471348+00
787	apollo	12:dc:6f:d5:5d:4f	mpop9016MP	authenticated	2025-04-24 06:02:25.471348+00
788	\N	92:6b:97:6a:82:b7	mpop9016MP	capture	2025-04-24 06:02:25.471348+00
789	apollo	92:6b:97:6a:82:b7	mpop9016MP	authenticated	2025-04-24 06:02:25.471348+00
790	apollo	92:6b:97:6a:82:b7	mpop9016MP	authenticated	2025-04-24 06:02:25.471348+00
791	apollo	92:6b:97:6a:82:b7	mpop9016MP	logout	2025-04-24 06:02:25.471348+00
792	apollo	12:dc:6f:d5:5d:4f	mpop9016MP	logout	2025-04-24 06:02:25.471348+00
793	mitzi@apolloglobal.net	f4:5c:89:ab:0d:d3	mpop9016MP	logout	2025-04-24 06:02:25.471348+00
794	\N	1a:c0:ed:de:e7:c8	mpop9016MP	capture	2025-04-24 06:02:25.471348+00
795	RES-201901-16	1a:c0:ed:de:e7:c8	mpop9016MP	authenticated	2025-04-24 06:02:25.471348+00
796	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-24 06:02:25.471348+00
797	RES-201901-16	1a:c0:ed:de:e7:c8	mpop9016MP	logout	2025-04-24 06:02:25.471348+00
798	\N	72:02:d8:0c:bf:8e	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
799	RES-201901-16	72:02:d8:0c:bf:8e	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
800	RES-201901-16	72:02:d8:0c:bf:8e	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
801	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
802	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
803	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
804	\N	f6:1c:7d:ae:91:d0	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
805	\N	ee:e5:0c:d6:c8:c0	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
806	\N	66:71:f1:2f:a1:f7	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
807	\N	6e:1d:a6:56:29:24	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
808	\N	6e:1d:a6:56:29:24	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
809	\N	6e:1d:a6:56:29:24	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
810	RES-201901-16	6e:1d:a6:56:29:24	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
811	RES-201901-16	6e:1d:a6:56:29:24	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
812	RES-201901-16	6e:1d:a6:56:29:24	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
813	\N	6e:1d:a6:56:29:24	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
814	RES-201901-16	6e:1d:a6:56:29:24	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
815	\N	32:3f:6e:8a:a8:05	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
816	RES-201901-16	6e:1d:a6:56:29:24	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
817	\N	32:3f:6e:8a:a8:05	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
818	\N	6e:1d:a6:56:29:24	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
819	\N	6e:1d:a6:56:29:24	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
820	RES-201901-16	6e:1d:a6:56:29:24	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
821	RES-201901-16	6e:1d:a6:56:29:24	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
822	ben@apolloglobal.net	32:3f:6e:8a:a8:05	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
823	RES-201901-16	6e:1d:a6:56:29:24	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
824	ben@apolloglobal.net	32:3f:6e:8a:a8:05	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
825	\N	b6:f1:4b:a2:61:70	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
826	\N	32:3f:6e:8a:a8:05	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
827	ben@apolloglobal.net	32:3f:6e:8a:a8:05	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
828	ben@apolloglobal.net	32:3f:6e:8a:a8:05	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
829	\N	32:3f:6e:8a:a8:05	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
830	ben@apolloglobal.net	32:3f:6e:8a:a8:05	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
831	ben@apolloglobal.net	32:3f:6e:8a:a8:05	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
832	\N	32:3f:6e:8a:a8:05	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
833	ben@apolloglobal.net	32:3f:6e:8a:a8:05	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
834	\N	a4:4e:31:88:ad:74	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
835	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
836	ben@apolloglobal.net	32:3f:6e:8a:a8:05	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
837	\N	06:8e:34:53:06:ee	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
838	luigi@apolloglobal.net	06:8e:34:53:06:ee	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
839	\N	0e:84:2a:42:13:e8	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
840	luigi@apolloglobal.net	0e:84:2a:42:13:e8	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
841	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
842	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
843	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
844	mencer@apollo.com.ph	d8:9e:61:24:76:f3	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
845	mencer@apollo.com.ph	d8:9e:61:24:76:f3	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
846	\N	12:dc:6f:d5:5d:4f	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
847	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
848	mencer@apollo.com.ph	d8:9e:61:24:76:f3	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
849	\N	8a:87:76:f8:2f:d1	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
850	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
851	\N	30:05:05:da:80:c2	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
852	\N	80:91:33:7a:84:1f	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
853	charchel@apollo.com.ph	80:91:33:7a:84:1f	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
854	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
855	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
856	\N	32:3f:6e:8a:a8:05	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
857	\N	32:3f:6e:8a:a8:05	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
858	ben@apolloglobal.net	32:3f:6e:8a:a8:05	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
859	ben@apolloglobal.net	32:3f:6e:8a:a8:05	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
860	\N	32:3f:6e:8a:a8:05	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
861	ben@apolloglobal.net	32:3f:6e:8a:a8:05	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
862	mencer@apollo.com.ph	d8:9e:61:24:76:f3	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
863	ben@apolloglobal.net	32:3f:6e:8a:a8:05	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
864	\N	32:3f:6e:8a:a8:05	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
865	ben@apolloglobal.net	32:3f:6e:8a:a8:05	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
866	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
867	mark@apollo.com.ph	8a:87:76:f8:2f:d1	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
868	\N	a4:4e:31:88:ad:74	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
869	ben@apolloglobal.net	32:3f:6e:8a:a8:05	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
870	\N	6e:1d:a6:56:29:24	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
871	\N	6e:1d:a6:56:29:24	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
872	\N	7a:c1:08:b3:c5:50	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
873	\N	32:3f:6e:8a:a8:05	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
874	ben@apolloglobal.net	32:3f:6e:8a:a8:05	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
875	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
876	ben@apolloglobal.net	32:3f:6e:8a:a8:05	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
877	\N	32:3f:6e:8a:a8:05	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
878	ben@apolloglobal.net	32:3f:6e:8a:a8:05	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
879	mencer@apollo.com.ph	d8:9e:61:24:76:f3	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
880	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
881	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
882	luigi@apolloglobal.net	0e:84:2a:42:13:e8	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
883	\N	0e:84:2a:42:13:e8	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
884	luigi@apolloglobal.net	06:8e:34:53:06:ee	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
885	\N	32:3f:6e:8a:a8:05	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
886	ben@apolloglobal.net	32:3f:6e:8a:a8:05	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
887	ben@apolloglobal.net	32:3f:6e:8a:a8:05	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
888	\N	32:3f:6e:8a:a8:05	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
889	ben@apolloglobal.net	32:3f:6e:8a:a8:05	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
890	ben@apolloglobal.net	32:3f:6e:8a:a8:05	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
891	ben@apolloglobal.net	32:3f:6e:8a:a8:05	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
892	\N	32:3f:6e:8a:a8:05	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
893	\N	42:07:1a:bf:f0:51	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
894	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
895	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
896	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
897	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
898	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
899	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
900	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
901	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
902	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
903	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
904	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
905	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
906	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
907	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
908	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
909	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
910	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
911	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
912	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
913	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
914	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
915	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
916	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
917	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
918	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
919	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
920	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
921	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
922	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
923	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
924	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
925	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
926	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
927	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
928	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
929	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
930	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
931	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
932	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
934	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
939	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
950	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
952	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
957	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
958	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
969	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
970	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
973	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
974	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
981	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
983	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
986	\N	d6:65:d9:57:71:7b	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
987	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
992	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
997	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1003	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1007	luigi@apolloglobal.net	0e:84:2a:42:13:e8	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
1010	luigi@apolloglobal.net	0e:84:2a:42:13:e8	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
1013	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
1014	\N	0e:84:2a:42:13:e8	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1018	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
1022	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
933	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
938	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
943	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
945	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
947	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
953	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
955	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
959	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
967	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
971	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
975	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
979	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
984	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
988	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
990	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
1001	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
1008	luigi@apolloglobal.net	0e:84:2a:42:13:e8	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
1011	luigi@apolloglobal.net	0e:84:2a:42:13:e8	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
1016	luigi@apolloglobal.net	0e:84:2a:42:13:e8	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
1021	luigi@apolloglobal.net	0e:84:2a:42:13:e8	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
1025	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
1026	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
935	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
940	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
944	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
948	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
949	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
954	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
960	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
962	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
965	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
976	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
980	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
985	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
989	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
994	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
996	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
1002	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
1004	\N	0e:84:2a:42:13:e8	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1019	\N	0e:84:2a:42:13:e8	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
936	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
941	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
951	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
961	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
964	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
978	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
982	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
993	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
998	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
1000	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1005	\N	0e:84:2a:42:13:e8	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1015	\N	0e:84:2a:42:13:e8	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1017	luigi@apolloglobal.net	0e:84:2a:42:13:e8	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
1020	\N	a4:4e:31:88:ad:74	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1024	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1027	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
937	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
942	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
946	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
956	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
963	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
966	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
968	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
972	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
977	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
991	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
995	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
999	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
1006	\N	0e:84:2a:42:13:e8	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1009	\N	0e:84:2a:42:13:e8	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1012	\N	a4:4e:31:88:ad:74	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1023	\N	0e:84:2a:42:13:e8	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1028	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
1029	luigi@apolloglobal.net	0e:84:2a:42:13:e8	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
1030	\N	0e:84:2a:42:13:e8	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1031	\N	0e:84:2a:42:13:e8	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1032	\N	0e:84:2a:42:13:e8	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1033	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1034	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
1035	\N	0e:84:2a:42:13:e8	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1036	luigi@apolloglobal.net	0e:84:2a:42:13:e8	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
1037	luigi@apolloglobal.net	0e:84:2a:42:13:e8	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
1038	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
1039	\N	0e:84:2a:42:13:e8	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1040	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1041	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
1042	\N	0e:84:2a:42:13:e8	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1043	\N	80:91:33:7a:84:1f	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1044	\N	06:8e:34:53:06:ee	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1045	luigi@apolloglobal.net	06:8e:34:53:06:ee	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
1046	charchel@apollo.com.ph	80:91:33:7a:84:1f	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
1047	luigi@apolloglobal.net	0e:84:2a:42:13:e8	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
1048	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
1049	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1050	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
1051	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
1052	mark@apollo.com.ph	a4:4e:31:88:ad:74	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
1053	charchel@apollo.com.ph	80:91:33:7a:84:1f	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
1054	luigi@apolloglobal.net	0e:84:2a:42:13:e8	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
1055	\N	0e:84:2a:42:13:e8	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1056	luigi@apolloglobal.net	0e:84:2a:42:13:e8	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
1057	luigi@apolloglobal.net	0e:84:2a:42:13:e8	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
1058	\N	0e:84:2a:42:13:e8	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1059	\N	0e:84:2a:42:13:e8	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1060	\N	0e:84:2a:42:13:e8	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1061	luigi@apolloglobal.net	06:8e:34:53:06:ee	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
1062	\N	06:8e:34:53:06:ee	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1063	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1064	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	authenticated	2025-04-24 08:24:58.485026+00
1065	ben@apolloglobal.net	a0:78:17:5c:e3:a7	mpop9016MP	logout	2025-04-24 08:24:58.485026+00
1066	\N	a0:78:17:5c:e3:a7	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1067	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1068	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1069	\N	32:3f:6e:8a:a8:05	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1070	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1071	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1072	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1073	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-04-24 08:24:58.485026+00
1074	\N	9a:9f:b3:0c:d5:0c	mpop9016MP	capture	2025-04-30 03:20:48.501496+00
1075	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 03:20:48.501496+00
1076	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 03:20:48.501496+00
1077	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-04-30 03:20:48.501496+00
1078	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	logout	2025-04-30 03:20:48.501496+00
1079	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-04-30 03:20:48.501496+00
1080	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-04-30 03:20:48.501496+00
1081	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-04-30 03:20:48.501496+00
1082	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 03:20:48.501496+00
1083	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-04-30 03:20:48.501496+00
1084	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 03:20:48.501496+00
1085	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 03:20:48.501496+00
1086	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-04-30 03:20:48.501496+00
1087	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 03:20:48.501496+00
1088	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 03:20:48.501496+00
1089	\N	a2:a4:ab:81:45:1e	mpop9016MP	capture	2025-04-30 03:20:48.501496+00
1090	charchel@apollo.com.ph	a2:a4:ab:81:45:1e	mpop9016MP	authenticated	2025-04-30 03:20:48.501496+00
1091	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 03:20:48.501496+00
1092	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 03:20:48.501496+00
1093	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-04-30 03:20:48.501496+00
1094	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1095	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1096	\N	a2:a4:ab:81:45:1e	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1097	Charchel@apollo.com.ph	a2:a4:ab:81:45:1e	mpop9016MP	authenticated	2025-04-30 09:42:49.74058+00
1098	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1099	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1100	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1101	\N	72:80:ea:58:b0:00	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1102	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1103	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1104	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-04-30 09:42:49.74058+00
1105	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1106	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1107	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-04-30 09:42:49.74058+00
1108	Charchel@apollo.com.ph	a2:a4:ab:81:45:1e	mpop9016MP	logout	2025-04-30 09:42:49.74058+00
1109	\N	ee:70:7d:a7:ae:3e	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1110	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1111	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-30 09:42:49.74058+00
1112	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1113	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-30 09:42:49.74058+00
1114	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-30 09:42:49.74058+00
1115	\N	2e:19:fc:b9:8b:96	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1116	\N	a2:d5:75:a2:c7:85	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1117	RES-201901-16	a2:d5:75:a2:c7:85	mpop9016MP	authenticated	2025-04-30 09:42:49.74058+00
1118	\N	5a:82:9d:bb:95:a0	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1119	\N	9e:46:d3:8f:21:b1	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1120	\N	5a:82:9d:bb:95:a0	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1121	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1122	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1123	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1124	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-04-30 09:42:49.74058+00
1125	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1126	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1127	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-04-30 09:42:49.74058+00
1128	\N	9a:9f:b3:0c:d5:0c	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1129	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1130	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1131	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-04-30 09:42:49.74058+00
1132	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1133	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-04-30 09:42:49.74058+00
1134	\N	9a:9f:b3:0c:d5:0c	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1135	\N	2e:4c:25:83:d8:e3	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1136	\N	9a:9f:b3:0c:d5:0c	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1137	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1138	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1139	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-04-30 09:42:49.74058+00
1140	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1141	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-04-30 09:42:49.74058+00
1142	\N	9a:9f:b3:0c:d5:0c	mpop9016MP	capture	2025-04-30 09:42:49.74058+00
1143	\N	3a:c4:e7:0a:03:60	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1144	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1145	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1146	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1147	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-05-01 04:58:58.632175+00
1148	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	logout	2025-05-01 04:58:58.632175+00
1149	\N	3a:c4:e7:0a:03:60	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1150	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1151	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1152	\N	3a:c4:e7:0a:03:60	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1153	RES-201901-16	3a:c4:e7:0a:03:60	mpop9016MP	authenticated	2025-05-01 04:58:58.632175+00
1154	RES-201901-16	3a:c4:e7:0a:03:60	mpop9016MP	logout	2025-05-01 04:58:58.632175+00
1155	\N	3a:c4:e7:0a:03:60	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1156	RES-201901-16	3a:c4:e7:0a:03:60	mpop9016MP	authenticated	2025-05-01 04:58:58.632175+00
1157	\N	3a:c4:e7:0a:03:60	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1158	RES-201901-16	3a:c4:e7:0a:03:60	mpop9016MP	authenticated	2025-05-01 04:58:58.632175+00
1159	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1160	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-05-01 04:58:58.632175+00
1161	\N	3a:c4:e7:0a:03:60	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1162	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1163	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1164	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-05-01 04:58:58.632175+00
1165	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1166	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1167	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-05-01 04:58:58.632175+00
1168	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1169	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1170	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1171	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-05-01 04:58:58.632175+00
1172	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-05-01 04:58:58.632175+00
1173	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1174	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1175	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-05-01 04:58:58.632175+00
1176	\N	3a:c4:e7:0a:03:60	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1177	\N	2e:4c:25:83:d8:e3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1178	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1179	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1180	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1181	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-05-01 04:58:58.632175+00
1182	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1183	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1184	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1185	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-05-01 04:58:58.632175+00
1186	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1187	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1188	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-05-01 04:58:58.632175+00
1189	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-05-01 04:58:58.632175+00
1190	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1191	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1192	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-05-01 04:58:58.632175+00
1193	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1194	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1195	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-05-01 04:58:58.632175+00
1196	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1197	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1198	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1199	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-05-01 04:58:58.632175+00
1200	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1201	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1202	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-05-01 04:58:58.632175+00
1203	\N	3a:c4:e7:0a:03:60	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1204	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1205	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1206	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-05-01 04:58:58.632175+00
1207	\N	3a:c4:e7:0a:03:60	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1208	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	logout	2025-05-01 04:58:58.632175+00
1209	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1210	\N	f4:5c:89:ab:0d:d3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1211	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	authenticated	2025-05-01 04:58:58.632175+00
1212	\N	46:b9:52:2b:e7:cb	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1213	RES-201901-16	f4:5c:89:ab:0d:d3	mpop9016MP	logout	2025-05-01 04:58:58.632175+00
1214	\N	46:b9:52:2b:e7:cb	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1215	RES-201901-16	46:b9:52:2b:e7:cb	mpop9016MP	authenticated	2025-05-01 04:58:58.632175+00
1216	RES-201901-16	46:b9:52:2b:e7:cb	mpop9016MP	logout	2025-05-01 04:58:58.632175+00
1217	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1218	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	authenticated	2025-05-01 04:58:58.632175+00
1219	jeeza@apollo.com.ph	f0:9e:4a:1e:dc:19	mpop9016MP	logout	2025-05-01 04:58:58.632175+00
1220	\N	5a:82:9d:bb:95:a0	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1221	\N	12:dc:6f:d5:5d:4f	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1222	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1223	\N	a0:c5:89:c6:6d:58	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1224	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1225	wifildap@apolloglobal.net	d8:9e:61:24:76:f3	mpop9016MP	authenticated	2025-05-01 04:58:58.632175+00
1226	\N	a0:c5:89:c6:6d:58	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1227	wifildap@apolloglobal.net	a0:c5:89:c6:6d:58	mpop9016MP	authenticated	2025-05-01 04:58:58.632175+00
1228	wifildap@apolloglobal.net	d8:9e:61:24:76:f3	mpop9016MP	logout	2025-05-01 04:58:58.632175+00
1229	\N	ac:e0:10:96:e0:93	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1230	\N	ac:e0:10:96:e0:93	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1231	wifildap@apolloglobal.net	ac:e0:10:96:e0:93	mpop9016MP	authenticated	2025-05-01 04:58:58.632175+00
1232	wifildap@apolloglobal.net	a0:c5:89:c6:6d:58	mpop9016MP	logout	2025-05-01 04:58:58.632175+00
1233	\N	a0:c5:89:c6:6d:58	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1234	wifildap@apolloglobal.net	ac:e0:10:96:e0:93	mpop9016MP	logout	2025-05-01 04:58:58.632175+00
1235	\N	d8:9e:61:24:76:f3	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
1236	\N	f0:9e:4a:1e:dc:19	mpop9016MP	capture	2025-05-01 04:58:58.632175+00
\.


--
-- Data for Name: acc_details; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.acc_details (id, "account_Number", pword, total_incoming_packets, total_outgoing_packets, last_active) FROM stdin;
\.


--
-- Data for Name: acc_sessions; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.acc_sessions (id, "account_Number", package, limit_count, limit_type, counter, incoming_packets, outgoing_packets, created_on, last_modified) FROM stdin;
8	charchel@apollo.com.ph	Unli	0	mb	0	2293982	20437498	2025-04-10 08:21:48.380877+00	2025-04-30 17:07:34.294808 +0800
2	mencer@apollo.com.ph	Unli	0	mb	0	6841861	139119778	2025-04-10 03:33:58.068605+00	2025-04-25 11:04:45.216017 +0800
9	RES-201901-16	Free	50000000	MB	0	0	0	2025-04-16 05:27:04.211696+00	2025-05-02 08:46:26.920501 +0800
10	apollo	Unli	0	mb	0	501891	6425841	2025-04-22 01:35:05.937805+00	2025-04-24 14:47:28.252668 +0800
5	mitzi@apolloglobal.net	Unli	0	mb	0	249642542	925393068	2025-04-10 05:00:23.863058+00	2025-04-24 15:03:32.247137 +0800
11	luigi@apolloglobal.net	Unli	0	mb	0	3385707	23658674	2025-04-25 00:55:42.615706+00	2025-04-28 09:49:58.155731 +0800
1	admin	Unli	0	mb	0	40501951	388945754	2025-04-10 03:14:32.833701+00	2025-04-23 17:44:14.686366 +0800
4	ben@apolloglobal.net	Unli	0	mb	0	1645798	19388079	2025-04-10 04:40:27.682197+00	2025-04-28 10:56:10.978398 +0800
13	wifildap@apolloglobal.net	Unli	0	mb	0	2858099	3820437	2025-05-02 05:48:50.808806+00	2025-05-02 14:19:33.424260 +0800
12	Charchel@apollo.com.ph	Unli	0	mb	0	1349030	2064308	2025-04-30 09:54:18.162145+00	2025-04-30 18:14:59.417614 +0800
3	mark@apollo.com.ph	Unli	0	mb	0	3722475	25169580	2025-04-10 03:35:03.685518+00	2025-04-28 09:10:49.983645 +0800
6	jeeza@apollo.com.ph	Unli	0	mb	0	469529	2677242	2025-04-10 05:17:08.56488+00	2025-05-02 09:11:14.686255 +0800
7	annanicole@apollo.com.ph	Unli	0	mb	0	190620064	751321937	2025-04-10 05:18:21.493906+00	2025-04-24 13:40:24.283135 +0800
\.


--
-- Data for Name: acc_transactions; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.acc_transactions (id, "account_Number", package, vlanid, gw_id, gw_sn, gw_address, gw_port, ssid, apmac, mac, device, ip, token, stage, total_incoming_packets, total_outgoing_packets, created_on, last_active) FROM stdin;
7	mencer@apollo.com.ph	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	d4:f3:2d:3a:7e:ce	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0	10.51.0.59	d19de9a523a25a225d5941fc4e81d7b0	authenticated	-1722516418	-144281850487	2025-04-10 03:37:37.547291+00	2025-04-14 10:21:54.962170 +0800
20	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	16:07:dd:3c:fa:c3	Mozilla/5.0 (Linux; Android 14; 2409BRN2CA Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.38 Mobile Safari/537.36	10.51.0.59	d33644fadf7dc76679a5e06e65fb9435	capture	0	0	2025-04-19 12:01:18.702819+00	2025-04-19 20:01:25.675627 +0800
12	ben@apolloglobal.net	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	a0:78:17:5c:e3:a7	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)	10.51.0.55	a7512ba92d80457f8f47a7e465602c67	capture	464568627	-24188412550	2025-04-10 08:23:06.874365+00	2025-04-28 10:57:17.266643 +0800
9	ben@apolloglobal.net	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	ca:d0:c1:e0:8d:6e	Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148	10.51.0.59	185d9c0b92c9ff7f7fa3ef9b6a45cbdf	capture	78239332	28732938877	2025-04-10 04:40:03.262343+00	2025-04-23 17:51:19.964913 +0800
29	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	0074.9c65.8d2c	4a:2b:46:c3:61:3e	Mozilla/5.0 (iPhone; CPU iPhone OS 18_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148	10.51.0.61	496f6a6046e9389c85872cc09a47808e	capture	0	0	2025-04-23 01:05:42.662548+00	2025-04-23 09:05:42.662548 +0800
11	charchel@apollo.com.ph	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	80:91:33:7a:84:1f	Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0	10.51.0.62	d714119546a7de59adc617aa02bc386c	logout	351321701	-5145972632	2025-04-10 08:21:36.838052+00	2025-04-28 09:11:56.979998 +0800
15	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	66:c3:c1:58:21:64	Mozilla/5.0 (Linux; Android 14; Infinix X6871 Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/134.0.6998.135 Mobile Safari/537.36	10.51.0.65	9172b54ac5d03eda1c311c3f43677350	capture	0	0	2025-04-11 04:41:29.909206+00	2025-04-11 12:41:29.909206 +0800
21	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	d4:a3:65:3b:01:46	Mozilla/5.0 (Linux; Android 14; 2409BRN2CA Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.38 Mobile Safari/537.36	10.51.0.59	735600245a8d21c611671ecea3e24f4e	capture	0	0	2025-04-19 12:03:03.897488+00	2025-04-19 20:03:20.800749 +0800
2	RES-201901-16	Free	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	0074.9c64.6f48	f4:5c:89:ab:0d:d3	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 (KHTML, like Gecko)	10.51.0.51	2f8f24f1f88cd2da7e97e93e999865ba	logout	1068773195	3048371491	2025-04-10 02:50:43.827911+00	2025-05-02 08:38:27.813919 +0800
53	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	5869.6cfa.681d	7a:c1:08:b3:c5:50	Mozilla/5.0 (Linux; Android 12; V2204 Build/SP1A.210812.003; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.99 Mobile Safari/537.36	10.51.0.55	fde59d7017e83d5bb1ee0ea305a568b9	capture	0	0	2025-04-25 07:51:17.884442+00	2025-04-25 15:51:17.884442 +0800
48	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	5869.6cfa.681d	b6:f1:4b:a2:61:70	Mozilla/5.0 (Linux; Android 14; SM-A156E Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.100 Mobile Safari/537.36	10.51.0.54	f4cb2ba0b0d91d4606349cf2abbc8b2e	capture	0	0	2025-04-24 18:20:58.135928+00	2025-04-25 02:20:58.135928 +0800
40	jeeza@apollo.com.ph	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	0074.9c65.8d2c	f0:9e:4a:1e:dc:19	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0	10.51.0.52	f65cac2b51a9d87a6492222d8720b7f7	capture	1095975	19455898	2025-04-24 05:40:18.244369+00	2025-05-02 14:55:23.132500 +0800
22	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	2e:19:fc:b9:8b:96	Mozilla/5.0 (Linux; Android 13; TECNO KJ6 Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.100 Mobile Safari/537.36	10.51.0.59	3d3dc4256508c1e1e15d334d31aa9ea8	capture	0	0	2025-04-20 13:05:13.460897+00	2025-04-22 21:47:33.131470 +0800
61	Charchel@apollo.com.ph	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	a2:a4:ab:81:45:1e	Mozilla/5.0 (Linux; Android 14; SM-A245F Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.110 Mobile Safari/537.36	10.51.0.53	3747128bf3eb23997a1bf2e130989b1f	logout	1349030	2064308	2025-04-30 09:06:59.201532+00	2025-04-30 18:14:59.417614 +0800
19	admin	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	72:80:ea:58:b0:00	okhttp/4.9.2	10.51.0.58	666491d239b9165150110e315e9b0f6e	authenticated	0	0	2025-04-16 01:34:23.272717+00	2025-04-22 17:41:18.344311 +0800
16	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	72:80:ea:58:b0:00	Mozilla/5.0 (Linux; Android 14; 2109119DG Build/UKQ1.231108.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.38 Mobile Safari/537.36	10.51.0.57	666491d239b9165150110e315e9b0f6e	capture	0	0	2025-04-14 09:12:30.044098+00	2025-04-14 17:12:30.044098 +0800
58	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	72:80:ea:58:b0:00	Mozilla/5.0 (Linux; Android 14; 2109119DG Build/UKQ1.240624.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.100 Mobile Safari/537.36	10.51.0.51	666491d239b9165150110e315e9b0f6e	capture	0	0	2025-04-28 06:18:57.391921+00	2025-04-28 14:18:57.391921 +0800
42	RES-201901-16	Free	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	0074.9c64.6f48	46:b9:52:2b:e7:cb	okhttp/4.9.2	10.51.0.53	25675c2f8566b7030f02ad232c74d8b5	logout	2683636834	1206039673	2025-04-24 06:07:40.418755+00	2025-05-02 08:46:26.920501 +0800
34	jeeza@apollo.com.ph	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	f0:9e:4a:1e:dc:19	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.98 Safari/537.36	10.51.0.56	f65cac2b51a9d87a6492222d8720b7f7	authenticated	5714696	120358277	2025-04-24 05:18:53.336864+00	2025-04-28 09:07:52.834306 +0800
13	admin	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	72:80:ea:58:b0:00	Mozilla/5.0 (Linux; Android 14; 2109119DG Build/UKQ1.231108.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/134.0.6998.135 Mobile Safari/537.36	10.51.0.51	666491d239b9165150110e315e9b0f6e	capture	46122143	436798256	2025-04-11 01:07:19.066834+00	2025-04-30 18:03:44.059085 +0800
59	wifildap@apolloglobal.net	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	d8:9e:61:24:76:f3	Mozilla/5.0 (Linux; Android 10; STK-L22 Build/HUAWEISTK-L22; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.100 Mobile Safari/537.36	10.51.0.55	2b17220559ae38745e7f220985382f69	capture	-1377908	-742738	2025-04-29 02:39:25.486573+00	2025-05-02 14:30:34.202218 +0800
23	mark@apollo.com.ph	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	8a:87:76:f8:2f:d1	Mozilla/5.0 (Linux; Android 13; 2201117PG Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.38 Mobile Safari/537.36	10.51.0.56	f0e3ea10a6786c90276c63750e51a294	logout	-10921001323	-160840771223	2025-04-22 00:41:26.746877+00	2025-04-25 12:05:20.262917 +0800
30	RES-201901-16	Free	233	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	0074.9c64.6f48	9a:9f:b3:0c:d5:0c	Mozilla/5.0 (iPhone; CPU iPhone OS 15_8_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148	10.233.2.2	f7dbb13073f81aa59967836338e1c95b	capture	1373291	13206776	2025-04-23 01:06:58.309526+00	2025-05-01 12:58:18.131419 +0800
68	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	0074.9c64.6f48	f4:5c:89:ab:0d:d3	Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:137.0) Gecko/20100101 Firefox/137.0	10.51.0.51	2f8f24f1f88cd2da7e97e93e999865ba	capture	0	0	2025-05-01 06:55:35.184384+00	2025-05-01 14:55:35.184384 +0800
54	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	42:07:1a:bf:f0:51	Mozilla/5.0 (Linux; Android 13; TECNO BG6 Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.111 Mobile Safari/537.36	10.51.0.67	057d94bc85170eeb094b3d72466cb5de	capture	0	0	2025-04-26 14:56:19.818716+00	2025-04-26 22:56:19.818716 +0800
10	jeeza@apollo.com.ph	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	f0:9e:4a:1e:dc:19	Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0	10.51.0.52	f65cac2b51a9d87a6492222d8720b7f7	authenticated	836864085	44975146000	2025-04-10 05:16:48.097269+00	2025-04-24 13:18:21.898031 +0800
14	charchel@apollo.com.ph	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	a2:a4:ab:81:45:1e	Mozilla/5.0 (Linux; Android 14; SM-A245F Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/134.0.6998.135 Mobile Safari/537.36	10.51.0.57	3747128bf3eb23997a1bf2e130989b1f	authenticated	93724704	14557682887	2025-04-11 01:27:28.384516+00	2025-04-30 17:07:34.294808 +0800
35	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	0074.9c65.8d2c	f0:9e:4a:1e:dc:19	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36	10.51.0.52	f65cac2b51a9d87a6492222d8720b7f7	capture	0	0	2025-04-24 05:19:58.004063+00	2025-04-24 13:19:58.004063 +0800
41	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	0074.9c65.8d2c	f0:9e:4a:1e:dc:19	Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36	10.51.0.52	f65cac2b51a9d87a6492222d8720b7f7	capture	0	0	2025-04-24 05:40:20.955906+00	2025-04-24 13:40:20.955906 +0800
43	apollo	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	92:6b:97:6a:82:b7	Mozilla/5.0 (Linux; Android 14; 23021RAAEG Build/UKQ1.230917.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.100 Mobile Safari/537.36	10.51.0.69	525ce85d8a7ba37da8999d1cc62982f9	logout	-1063256	-24974115	2025-04-24 06:40:49.482266+00	2025-04-24 14:46:05.191870 +0800
49	luigi@apolloglobal.net	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	06:8e:34:53:06:ee	Mozilla/5.0 (iPhone; CPU iPhone OS 18_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148	10.51.0.58	e44d47e7ee9d320b0133f2a2231abf28	capture	-33191311064	-199509328334	2025-04-25 00:55:05.370684+00	2025-04-28 10:19:49.302989 +0800
31	RES-201901-16	Free	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	0074.9c65.8d2c	46:b9:52:2b:e7:cb	Mozilla/5.0 (Linux; Android 13; 2201117PG Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.38 Mobile Safari/537.36	10.51.0.67	25675c2f8566b7030f02ad232c74d8b5	capture	106145	62474	2025-04-23 08:54:28.416887+00	2025-04-24 14:06:17.345073 +0800
65	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	0074.9c64.6f48	9e:46:d3:8f:21:b1	Mozilla/5.0 (Linux; Android 14; V2332 Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.100 Mobile Safari/537.36	10.51.0.52	a7de769dd7f7e161ab2ab676e0ef5dc3	capture	0	0	2025-05-01 02:32:47.97457+00	2025-05-01 10:32:47.974570 +0800
63	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	2e:19:fc:b9:8b:96	Mozilla/5.0 (Linux; Android 13; TECNO KJ6 Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.110 Mobile Safari/537.36	10.51.0.54	3d3dc4256508c1e1e15d334d31aa9ea8	capture	0	0	2025-04-30 23:15:45.229682+00	2025-05-01 07:15:45.229682 +0800
69	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	0074.9c64.6f48	46:b9:52:2b:e7:cb	Mozilla/5.0 (Linux; Android 13; 2201117PG Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.110 Mobile Safari/537.36	10.51.0.53	25675c2f8566b7030f02ad232c74d8b5	capture	0	0	2025-05-02 00:46:03.005479+00	2025-05-02 08:46:03.005479 +0800
64	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	5a:82:9d:bb:95:a0	Mozilla/5.0 (Linux; Android 14; V2332 Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.100 Mobile Safari/537.36	10.51.0.51	7cb0e1288a6930acb54e72fedfd205f3	capture	0	0	2025-05-01 02:32:14.020869+00	2025-05-02 10:40:30.939909 +0800
25	apollo	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	1e:f4:0c:75:67:af	Mozilla/5.0 (iPhone; CPU iPhone OS 15_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148	10.51.0.61	b48dca56ce420cf32aa82e61202de1c8	logout	-14957798	-211823786	2025-04-22 01:37:49.021909+00	2025-04-22 09:54:52.290454 +0800
8	mark@apollo.com.ph	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	8a:87:76:f8:2f:d1	Mozilla/5.0 (Android 13; Mobile; rv:139.0) Gecko/139.0 Firefox/139.0	10.51.0.56	f0e3ea10a6786c90276c63750e51a294	capture	-200346497	-4695058221	2025-04-10 04:30:35.629223+00	2025-04-16 15:19:39.836227 +0800
44	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	72:80:ea:58:b0:00	Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36	10.51.0.58	666491d239b9165150110e315e9b0f6e	capture	0	0	2025-04-24 07:12:59.351627+00	2025-04-24 15:12:59.351627 +0800
24	apollo	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	12:dc:6f:d5:5d:4f	Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148	10.51.0.54	a6d0a62a31d28ef373bb6e751db2994d	capture	17879849	258038838	2025-04-22 01:34:33.230431+00	2025-05-02 12:40:07.194870 +0800
36	RES-201901-16	Free	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	5869.6cfa.681d	1a:c0:ed:de:e7:c8	Mozilla/5.0 (Linux; Android 15; 23113RKC6G Build/AQ3A.240912.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.100 Mobile Safari/537.36	10.51.0.51	3d724e9ec2d43aa5594e48fbdc8d90b0	logout	-379109139	707422905	2025-04-24 05:30:14.386915+00	2025-04-24 15:13:37.089480 +0800
50	luigi@apolloglobal.net	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	0e:84:2a:42:13:e8	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)	10.51.0.52	1cfb87ca228c447fb61f829bc6e3d463	capture	33026925864	197848792214	2025-04-25 00:56:25.104463+00	2025-04-28 09:23:59.974371 +0800
55	RES-201901-16	Free	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	0074.9c64.6f48	a2:d5:75:a2:c7:85	Mozilla/5.0 (Linux; Android 13; TECNO KJ6 Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.110 Mobile Safari/537.36	10.51.0.52	3df7336b556a2f8c24fae885200c21ae	authenticated	40829365	870331585	2025-04-27 10:40:24.4961+00	2025-05-01 07:16:33.694930 +0800
60	\N	\N	233	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	0074.9c65.83bc	f4:5c:89:ab:0d:d3	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36	10.233.2.2	2f8f24f1f88cd2da7e97e93e999865ba	capture	0	0	2025-04-30 03:36:58.876336+00	2025-04-30 11:36:58.876336 +0800
62	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	0074.9c64.6f48	ee:70:7d:a7:ae:3e	Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148	10.51.0.53	bf92ea18abc0e6ac26ab8ee35482a892	capture	0	0	2025-04-30 15:10:57.328241+00	2025-04-30 23:10:57.328241 +0800
56	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	0074.9c65.8d2c	d6:65:d9:57:71:7b	Mozilla/5.0 (Linux; Android 11; RMX3231 Build/RP1A.201005.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.111 Mobile Safari/537.36	10.51.0.52	b8c92cfe7a7cbdf07751a6920388a611	capture	0	0	2025-04-27 21:51:02.474497+00	2025-04-28 05:51:02.474497 +0800
70	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	f0:9e:4a:1e:dc:19	Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0	10.51.0.54	f65cac2b51a9d87a6492222d8720b7f7	capture	0	0	2025-05-02 01:08:54.671135+00	2025-05-02 09:08:54.671135 +0800
5	mark@apollo.com.ph	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	8a:87:76:f8:2f:d1	Mozilla/5.0 (Linux; Android 13; 2201117PG Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/134.0.6998.135 Mobile Safari/537.36	10.51.0.56	f0e3ea10a6786c90276c63750e51a294	authenticated	-21664036323	-186432667588	2025-04-10 03:34:39.447744+00	2025-04-16 04:13:58.912448 +0800
45	RES-201901-16	Free	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	5869.6cfa.681d	72:02:d8:0c:bf:8e	Mozilla/5.0 (Linux; Android 11; SM-N986U Build/RP1A.200720.012; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.100 Mobile Safari/537.36	10.51.0.53	6e8d83a89ddebbc8169e2ad6406b7609	logout	1355655	10404401	2025-04-24 08:36:49.345065+00	2025-04-24 16:40:57.099243 +0800
51	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	8a:87:76:f8:2f:d1	Mozilla/5.0 (Linux; Android 13; 2201117PG Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.110 Mobile Safari/537.36	10.51.0.54	f0e3ea10a6786c90276c63750e51a294	capture	0	0	2025-04-25 01:59:06.756179+00	2025-04-25 09:59:06.756179 +0800
26	RES-201901-16	Free	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	0074.9c65.8d2c	6e:1d:a6:56:29:24	Mozilla/5.0 (Linux; Android 14; 2109119DG Build/UKQ1.231108.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.38 Mobile Safari/537.36	10.51.0.52	c3bb89ecf90c6b71167d54e71f089e7f	capture	-2118197807	-1507878008	2025-04-22 09:40:43.809781+00	2025-04-25 14:44:13.854464 +0800
38	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	0074.9c65.8d2c	f6:1c:7d:ae:91:d0	Mozilla/5.0 (Linux; Android 11; TECNO BD4a Build/RP1A.200720.011; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.38 Mobile Safari/537.36	10.51.0.55	ad0d673ebbe9044afcb4bed9f62c67fc	capture	0	0	2025-04-24 05:30:15.544316+00	2025-04-24 17:14:21.064172 +0800
6	mark@apollo.com.ph	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	a4:4e:31:88:ad:74	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36	10.51.0.53	2365f5edb827a1704d40a6434475d7c1	logout	33284333618	360502958521	2025-04-10 03:37:12.791926+00	2025-04-28 09:10:49.983645 +0800
17	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	5a:82:9d:bb:95:a0	Mozilla/5.0 (Linux; Android 14; V2332 Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/134.0.6998.135 Mobile Safari/537.36	10.51.0.57	7cb0e1288a6930acb54e72fedfd205f3	capture	0	0	2025-04-14 22:33:05.039817+00	2025-04-15 06:33:05.039817 +0800
1	annanicole@apollo.com.ph	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	ee:e5:0c:d6:c8:c0	Mozilla/5.0 (Linux; Android 11; TECNO BD4a Build/RP1A.200720.011; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/134.0.6998.135 Mobile Safari/537.36	10.51.0.54	9a451ad40ba89f7cf91ae1717f96bad4	capture	-14088677260	-9463978417	2025-04-08 09:55:49.868473+00	2025-04-24 17:14:48.672365 +0800
18	mencer@apollo.com.ph	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	d8:9e:61:24:76:f3	Mozilla/5.0 (Linux; Android 10; STK-L22 Build/HUAWEISTK-L22; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.38 Mobile Safari/537.36	10.51.0.59	2b17220559ae38745e7f220985382f69	logout	26026553	659801952	2025-04-15 00:34:46.021359+00	2025-04-25 11:04:45.216017 +0800
37	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	5869.6cfa.681d	1a:c0:ed:de:e7:c8	Mozilla/5.0 (Linux; Android 15; 23113RKC6G Build/AQ3A.240912.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.100 Mobile Safari/537.36	10.51.0.51	3d724e9ec2d43aa5594e48fbdc8d90b0	capture	0	0	2025-04-24 05:30:14.081958+00	2025-04-24 13:30:14.081958 +0800
32	RES-201901-16	Free	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	0074.9c65.8d2c	6e:1d:a6:56:29:24	okhttp/4.9.2	10.51.0.63	c3bb89ecf90c6b71167d54e71f089e7f	authenticated	0	0	2025-04-23 09:49:25.666339+00	2025-04-24 09:18:57.661571 +0800
66	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	2e:4c:25:83:d8:e3	Mozilla/5.0 (iPhone; CPU iPhone OS 15_8_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148	10.51.0.54	3aa6ac249097f740f63c2eda1dd80605	capture	0	0	2025-05-01 04:32:00.866007+00	2025-05-01 14:53:18.416470 +0800
72	wifildap@apolloglobal.net	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	ac:e0:10:96:e0:93	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36	10.51.0.55	44a80962418ee8444b9eedfdf3db3630	logout	-44247884	-22728379	2025-05-02 06:02:37.490473+00	2025-05-02 14:19:33.424260 +0800
71	wifildap@apolloglobal.net	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	a0:c5:89:c6:6d:58	Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36	10.51.0.54	63929891ffc2ff6d3f06ad4564fb5143	capture	53173417	30236981	2025-05-02 05:44:05.027781+00	2025-05-02 14:18:30.359851 +0800
4	mencer@apollo.com.ph	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	d8:9e:61:24:76:f3	Mozilla/5.0 (Linux; Android 10; STK-L22 Build/HUAWEISTK-L22; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/134.0.6998.135 Mobile Safari/537.36	10.51.0.57	2b17220559ae38745e7f220985382f69	authenticated	2039510464	153589460626	2025-04-10 03:33:08.780316+00	2025-04-16 04:14:01.213776 +0800
27	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	72:80:ea:58:b0:00	Mozilla/5.0 (Linux; Android 14; 2109119DG Build/UKQ1.231108.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.100 Mobile Safari/537.36	10.51.0.58	666491d239b9165150110e315e9b0f6e	capture	0	0	2025-04-23 00:45:19.706425+00	2025-04-23 08:45:19.706425 +0800
28	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	0074.9c65.8d2c	6e:1d:a6:56:29:24	Mozilla/5.0 (Linux; Android 14; 2109119DG Build/UKQ1.231108.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.100 Mobile Safari/537.36	10.51.0.61	c3bb89ecf90c6b71167d54e71f089e7f	capture	0	0	2025-04-23 00:46:14.553147+00	2025-04-23 08:46:14.553147 +0800
57	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	0e:84:2a:42:13:e8	Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0	10.51.0.52	1cfb87ca228c447fb61f829bc6e3d463	capture	0	0	2025-04-28 00:42:19.31579+00	2025-04-28 08:42:19.315790 +0800
47	ben@apolloglobal.net	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	32:3f:6e:8a:a8:05	Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148	10.51.0.51	75db88ba2399a7e56fc5caad50f1aac5	capture	90530241	2367558519	2025-04-24 09:58:46.192124+00	2025-04-28 11:41:27.576575 +0800
52	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	0074.9c65.8d2c	6e:1d:a6:56:29:24	Mozilla/5.0 (Linux; Android 14; 2109119DG Build/UKQ1.240624.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.100 Mobile Safari/537.36	10.51.0.52	c3bb89ecf90c6b71167d54e71f089e7f	capture	0	0	2025-04-25 06:43:23.315775+00	2025-04-25 14:43:23.315775 +0800
3	annanicole@apollo.com.ph	Unli	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	30:05:05:da:80:c2	Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15	10.51.0.70	2fa38d9822ef62a9dc4ed27773525a96	capture	14856317925	14170615558	2025-04-10 03:30:35.173494+00	2025-04-25 10:02:17.141135 +0800
46	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	0074.9c65.8d2c	66:71:f1:2f:a1:f7	Mozilla/5.0 (Linux; Android 14; SM-A245F Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.100 Mobile Safari/537.36	10.51.0.53	cc450341413e8af9d7bba324c6e13a65	capture	0	0	2025-04-24 09:15:14.011449+00	2025-04-24 17:15:14.011449 +0800
39	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	APOLLO	0074.9c65.8d2c	ee:e5:0c:d6:c8:c0	Mozilla/5.0 (Linux; Android 11; TECNO BD4a Build/RP1A.200720.011; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.7049.38 Mobile Safari/537.36	10.51.0.53	9a451ad40ba89f7cf91ae1717f96bad4	capture	0	0	2025-04-24 05:30:15.706396+00	2025-04-24 13:30:15.706396 +0800
33	\N	\N	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	0074.9c65.8d2c	46:b9:52:2b:e7:cb	Mozilla/5.0 (Android 13; Mobile; rv:139.0) Gecko/139.0 Firefox/139.0	10.51.0.65	25675c2f8566b7030f02ad232c74d8b5	capture	0	0	2025-04-24 04:29:00.808209+00	2025-04-24 12:29:00.808209 +0800
67	RES-201901-16	Free	51	mpop9016MP	mpop9016MP	1.2.3.4	2060	ZEEP-TEST	0074.9c64.6f48	3a:c4:e7:0a:03:60	Mozilla/5.0 (iPhone; CPU iPhone OS 15_8_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148	10.51.0.52	b94b342373697ef562c9c24e88b67e16	capture	35372	373360	2025-05-01 04:59:33.923894+00	2025-05-01 16:45:56.347742 +0800
\.


--
-- Data for Name: access_auth_logs; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.access_auth_logs (id, username, stage, gw_id, date, mac) FROM stdin;
\.


--
-- Data for Name: accounting; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.accounting (username, time_stamp, acctstatustype, acctsessionid, nasidentifier, auth_mode, device, acctinputoctets, acctoutputoctets, framedipaddress, mac, created_at) FROM stdin;
\.


--
-- Data for Name: admin_users; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.admin_users (id, username, password, first_name, last_name, role_id, mpop_id, created_by_id, created_on, modified_by_id, modified_on) FROM stdin;
\.


--
-- Data for Name: alembic_version; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.alembic_version (version_num) FROM stdin;
\.


--
-- Data for Name: announcements; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.announcements (id, name, path, gw_id, modified_by_id, modified_on, status, created_by_id, created_on) FROM stdin;
\.


--
-- Data for Name: auto_complete; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.auto_complete (id, command, device_model, suggestion_list) FROM stdin;
\.


--
-- Data for Name: certified; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.certified (id, mac, common_name, cert_data, month_data, last_record, last_active) FROM stdin;
\.


--
-- Data for Name: client_auth_logs; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.client_auth_logs (id, uname, stage, gw_id, date, mac) FROM stdin;
\.


--
-- Data for Name: client_devices; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.client_devices (id, mac, total_incoming_packets, total_outgoing_packets, last_active) FROM stdin;
\.


--
-- Data for Name: client_list; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.client_list (id, band, down, ip, macc, manufacturer, os, rssi, serial_num, ssid, traffic, up) FROM stdin;
\.


--
-- Data for Name: client_sessions; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.client_sessions (id, device_id, package_id, counter, created_on, date_modified, incoming_packets, outgoing_packets, limit_reached, cluster_id) FROM stdin;
\.


--
-- Data for Name: client_transactions; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.client_transactions (id, uname, gw_sn, ip, gw_address, gw_port, device_id, apmac, ssid, vlanid, token, stage, package_id, device, date_modified, gw_id, created_on, cluster_id) FROM stdin;
\.


--
-- Data for Name: cpe_response_log; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.cpe_response_log (id, method, payload, serial_num) FROM stdin;
\.


--
-- Data for Name: data_limits; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.data_limits (id, modified_by_id, modified_on, value, access_type, gw_id, limit_type, status, created_by_id, created_on) FROM stdin;
\.


--
-- Data for Name: device; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.device (id, activated, date_created, date_modified, date_offline, device_name, device_type, location, mac_address, model, parent, second_wan_mac_address, serial_number, status, wan_ip) FROM stdin;
\.


--
-- Data for Name: device_logs; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.device_logs (id, offtime, ontime, reason, serial_num, type, update_time) FROM stdin;
\.


--
-- Data for Name: device_model_parameters; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.device_model_parameters (id, con_req_url_parameter, hardware_ver_parameter, mac_address_parameter, management_ip_parameter, manufacturer, model, public_ip_parameter, second_wan_mac, software_ver_parameter, udp_con_req_url_parameter) FROM stdin;
\.


--
-- Data for Name: device_traffic_24h; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.device_traffic_24h (id, date, rx, serial_num, "time", tx) FROM stdin;
\.


--
-- Data for Name: device_traffic_daily; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.device_traffic_daily (id, date, rx, serial_num, tx) FROM stdin;
\.


--
-- Data for Name: devices; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.devices (id, mac, free_data, month_data, last_active, last_record, con_req_url, cpu_usage, cwmp_cycle_end, device_alias, hardware_ver, mac_address, management_ip, manufacturer, memory_usage, model, oui, public_ip, second_wan_mac, serial_num, software_ver, ssids, udp_con_req_url) FROM stdin;
\.


--
-- Data for Name: gateway_group; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.gateway_group (id, name, created_by_id, created_on, modified_by_id, modified_on, status) FROM stdin;
\.


--
-- Data for Name: gateway_groups; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.gateway_groups (id, gw_id, group_id) FROM stdin;
\.


--
-- Data for Name: gateways; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.gateways (id, gw_id, name, modified_on, modified_by_id, status, created_by_id, created_on) FROM stdin;
\.


--
-- Data for Name: group_announcements; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.group_announcements (id, name, path, status, group_id, modified_by_id, modified_on, created_by_id, created_on) FROM stdin;
\.


--
-- Data for Name: group_command; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.group_command (id, command, description, model, parent) FROM stdin;
\.


--
-- Data for Name: group_ssid; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.group_ssid (id, auth, downlink, encryption_mode, forward_mode, gateway_id, limitless, parent, passphrase, portal_ip, portal_url, seamless, ssid, uplink, vlan_id, wlan_id) FROM stdin;
\.


--
-- Data for Name: groups; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.groups (id, child, date_created, date_modified, group_name, location, parent) FROM stdin;
\.


--
-- Data for Name: httprequestlog; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.httprequestlog (id, cookie, device_status, last_request, serial_num) FROM stdin;
\.


--
-- Data for Name: logos; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.logos (id, name, path, status, gw_id, modified_by_id, modified_on, created_by_id, created_on) FROM stdin;
\.


--
-- Data for Name: packages; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.packages (id, title, description, limit_count, limit_type, package_type, price, validity) FROM stdin;
\.


--
-- Data for Name: radio_info; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.radio_info (id, band_width, channel, gather_time, power, radio_index, sn, upload_time, utilization) FROM stdin;
\.


--
-- Data for Name: redirect_links; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.redirect_links (id, gw_id, url, status, modified_by_id, modified_on, created_by_id, created_on) FROM stdin;
\.


--
-- Data for Name: registered_users; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.registered_users (id, uname, registered_data, month_data, last_active, last_record) FROM stdin;
\.


--
-- Data for Name: roles; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.roles (id, role) FROM stdin;
\.


--
-- Data for Name: taskhandler; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.taskhandler (id, method, optional, parameters, serial_num) FROM stdin;
\.


--
-- Data for Name: webcli_response_log; Type: TABLE DATA; Schema: public; Owner: wildweasel
--

COPY public.webcli_response_log (id, command_output, command_used, device_sn, time_saved) FROM stdin;
\.


--
-- Name: acc_auth_logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: wildweasel
--

SELECT pg_catalog.setval('public.acc_auth_logs_id_seq', 1236, true);


--
-- Name: acc_details_id_seq; Type: SEQUENCE SET; Schema: public; Owner: wildweasel
--

SELECT pg_catalog.setval('public.acc_details_id_seq', 1, false);


--
-- Name: acc_sessions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: wildweasel
--

SELECT pg_catalog.setval('public.acc_sessions_id_seq', 13, true);


--
-- Name: acc_transactions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: wildweasel
--

SELECT pg_catalog.setval('public.acc_transactions_id_seq', 72, true);


--
-- Name: access_auth_logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: wildweasel
--

SELECT pg_catalog.setval('public.access_auth_logs_id_seq', 1, false);


--
-- Name: admin_users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: wildweasel
--

SELECT pg_catalog.setval('public.admin_users_id_seq', 1, false);


--
-- Name: announcements_id_seq; Type: SEQUENCE SET; Schema: public; Owner: wildweasel
--

SELECT pg_catalog.setval('public.announcements_id_seq', 1, false);


--
-- Name: certified_id_seq; Type: SEQUENCE SET; Schema: public; Owner: wildweasel
--

SELECT pg_catalog.setval('public.certified_id_seq', 1, false);


--
-- Name: client_auth_logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: wildweasel
--

SELECT pg_catalog.setval('public.client_auth_logs_id_seq', 1, false);


--
-- Name: client_devices_id_seq; Type: SEQUENCE SET; Schema: public; Owner: wildweasel
--

SELECT pg_catalog.setval('public.client_devices_id_seq', 1, false);


--
-- Name: client_sessions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: wildweasel
--

SELECT pg_catalog.setval('public.client_sessions_id_seq', 1, false);


--
-- Name: client_transactions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: wildweasel
--

SELECT pg_catalog.setval('public.client_transactions_id_seq', 1, false);


--
-- Name: data_limits_id_seq; Type: SEQUENCE SET; Schema: public; Owner: wildweasel
--

SELECT pg_catalog.setval('public.data_limits_id_seq', 1, false);


--
-- Name: devices_id_seq; Type: SEQUENCE SET; Schema: public; Owner: wildweasel
--

SELECT pg_catalog.setval('public.devices_id_seq', 1, false);


--
-- Name: gateway_group_id_seq; Type: SEQUENCE SET; Schema: public; Owner: wildweasel
--

SELECT pg_catalog.setval('public.gateway_group_id_seq', 1, false);


--
-- Name: gateway_groups_id_seq; Type: SEQUENCE SET; Schema: public; Owner: wildweasel
--

SELECT pg_catalog.setval('public.gateway_groups_id_seq', 1, false);


--
-- Name: gateways_id_seq; Type: SEQUENCE SET; Schema: public; Owner: wildweasel
--

SELECT pg_catalog.setval('public.gateways_id_seq', 1, false);


--
-- Name: group_announcements_id_seq; Type: SEQUENCE SET; Schema: public; Owner: wildweasel
--

SELECT pg_catalog.setval('public.group_announcements_id_seq', 1, false);


--
-- Name: hibernate_sequence; Type: SEQUENCE SET; Schema: public; Owner: wildweasel
--

SELECT pg_catalog.setval('public.hibernate_sequence', 1, false);


--
-- Name: logos_id_seq; Type: SEQUENCE SET; Schema: public; Owner: wildweasel
--

SELECT pg_catalog.setval('public.logos_id_seq', 1, false);


--
-- Name: packages_id_seq; Type: SEQUENCE SET; Schema: public; Owner: wildweasel
--

SELECT pg_catalog.setval('public.packages_id_seq', 1, false);


--
-- Name: redirect_links_id_seq; Type: SEQUENCE SET; Schema: public; Owner: wildweasel
--

SELECT pg_catalog.setval('public.redirect_links_id_seq', 1, false);


--
-- Name: registered_users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: wildweasel
--

SELECT pg_catalog.setval('public.registered_users_id_seq', 1, false);


--
-- Name: roles_id_seq; Type: SEQUENCE SET; Schema: public; Owner: wildweasel
--

SELECT pg_catalog.setval('public.roles_id_seq', 1, false);


--
-- Name: session_id_seq; Type: SEQUENCE SET; Schema: public; Owner: wildweasel
--

SELECT pg_catalog.setval('public.session_id_seq', 1, false);


--
-- Name: acc_auth_logs acc_auth_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: wildweasel
--

ALTER TABLE ONLY public.acc_auth_logs
    ADD CONSTRAINT acc_auth_logs_pkey PRIMARY KEY (id);


--
-- Name: acc_details acc_details_pkey; Type: CONSTRAINT; Schema: public; Owner: wildweasel
--

ALTER TABLE ONLY public.acc_details
    ADD CONSTRAINT acc_details_pkey PRIMARY KEY (id);


--
-- Name: acc_sessions acc_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: wildweasel
--

ALTER TABLE ONLY public.acc_sessions
    ADD CONSTRAINT acc_sessions_pkey PRIMARY KEY (id);


--
-- Name: acc_transactions acc_transactions_pkey; Type: CONSTRAINT; Schema: public; Owner: wildweasel
--

ALTER TABLE ONLY public.acc_transactions
    ADD CONSTRAINT acc_transactions_pkey PRIMARY KEY (id);


--
-- Name: auto_complete auto_complete_pkey; Type: CONSTRAINT; Schema: public; Owner: wildweasel
--

ALTER TABLE ONLY public.auto_complete
    ADD CONSTRAINT auto_complete_pkey PRIMARY KEY (id);


--
-- Name: client_list client_list_pkey; Type: CONSTRAINT; Schema: public; Owner: wildweasel
--

ALTER TABLE ONLY public.client_list
    ADD CONSTRAINT client_list_pkey PRIMARY KEY (id);


--
-- Name: client_sessions client_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: wildweasel
--

ALTER TABLE ONLY public.client_sessions
    ADD CONSTRAINT client_sessions_pkey PRIMARY KEY (id);


--
-- Name: cpe_response_log cpe_response_log_pkey; Type: CONSTRAINT; Schema: public; Owner: wildweasel
--

ALTER TABLE ONLY public.cpe_response_log
    ADD CONSTRAINT cpe_response_log_pkey PRIMARY KEY (id);


--
-- Name: device_logs device_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: wildweasel
--

ALTER TABLE ONLY public.device_logs
    ADD CONSTRAINT device_logs_pkey PRIMARY KEY (id);


--
-- Name: device_model_parameters device_model_parameters_pkey; Type: CONSTRAINT; Schema: public; Owner: wildweasel
--

ALTER TABLE ONLY public.device_model_parameters
    ADD CONSTRAINT device_model_parameters_pkey PRIMARY KEY (id);


--
-- Name: device device_pkey; Type: CONSTRAINT; Schema: public; Owner: wildweasel
--

ALTER TABLE ONLY public.device
    ADD CONSTRAINT device_pkey PRIMARY KEY (id);


--
-- Name: device_traffic_24h device_traffic_24h_pkey; Type: CONSTRAINT; Schema: public; Owner: wildweasel
--

ALTER TABLE ONLY public.device_traffic_24h
    ADD CONSTRAINT device_traffic_24h_pkey PRIMARY KEY (id);


--
-- Name: device_traffic_daily device_traffic_daily_pkey; Type: CONSTRAINT; Schema: public; Owner: wildweasel
--

ALTER TABLE ONLY public.device_traffic_daily
    ADD CONSTRAINT device_traffic_daily_pkey PRIMARY KEY (id);


--
-- Name: group_command group_command_pkey; Type: CONSTRAINT; Schema: public; Owner: wildweasel
--

ALTER TABLE ONLY public.group_command
    ADD CONSTRAINT group_command_pkey PRIMARY KEY (id);


--
-- Name: group_ssid group_ssid_pkey; Type: CONSTRAINT; Schema: public; Owner: wildweasel
--

ALTER TABLE ONLY public.group_ssid
    ADD CONSTRAINT group_ssid_pkey PRIMARY KEY (id);


--
-- Name: groups groups_pkey; Type: CONSTRAINT; Schema: public; Owner: wildweasel
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_pkey PRIMARY KEY (id);


--
-- Name: httprequestlog httprequestlog_pkey; Type: CONSTRAINT; Schema: public; Owner: wildweasel
--

ALTER TABLE ONLY public.httprequestlog
    ADD CONSTRAINT httprequestlog_pkey PRIMARY KEY (id);


--
-- Name: radio_info radio_info_pkey; Type: CONSTRAINT; Schema: public; Owner: wildweasel
--

ALTER TABLE ONLY public.radio_info
    ADD CONSTRAINT radio_info_pkey PRIMARY KEY (id);


--
-- Name: taskhandler taskhandler_pkey; Type: CONSTRAINT; Schema: public; Owner: wildweasel
--

ALTER TABLE ONLY public.taskhandler
    ADD CONSTRAINT taskhandler_pkey PRIMARY KEY (id);


--
-- Name: webcli_response_log webcli_response_log_pkey; Type: CONSTRAINT; Schema: public; Owner: wildweasel
--

ALTER TABLE ONLY public.webcli_response_log
    ADD CONSTRAINT webcli_response_log_pkey PRIMARY KEY (id);


--
-- PostgreSQL database dump complete
--

