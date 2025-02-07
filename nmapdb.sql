CREATE TABLE IF NOT EXISTS hosts (
    ip          VARCHAR(16) PRIMARY KEY NOT NULL,
    mac         VARCHAR(18),
    hostname    VARCHAR(129),
    protocol    VARCHAR(5) DEFAULT 'ipv4',
    os_name     TEXT,
    os_family   TEXT,
    os_accuracy INTEGER,
    os_gen      TEXT,
    last_update TIMESTAMP,
    state       VARCHAR(8) DEFAULT 'down',
    mac_vendor  TEXT,
    whois       TEXT
);

CREATE TABLE IF NOT EXISTS ports (
    ip          VARCHAR(16) NOT NULL,
    port        INTEGER NOT NULL,
    protocol    VARCHAR(4) NOT NULL,
    name        VARCHAR(33),
    state       VARCHAR(33) DEFAULT 'closed',
    service     TEXT,
    info        TEXT,
    PRIMARY KEY (ip, port, protocol),
    CONSTRAINT fk_ports_hosts FOREIGN KEY (ip) REFERENCES hosts(ip) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS smb (
    ip		VARCHAR(16) NOT NULL,
    port        INTEGER NOT NULL,
    protocol    VARCHAR(4) NOT NULL,
    smb1	VARCHAR(16) NOT NULL,
    smb2	VARCHAR(16) NOT NULL,
    smb3	VARCHAR(16) NOT NULL,
    PRIMARY KEY (ip, port, protocol),
    CONSTRAINT fk_smb_hosts FOREIGN KEY (ip) REFERENCES hosts(ip) ON DELETE CASCADE
);



CREATE TRIGGER IF NOT EXISTS fki_ports_hosts_ip
BEFORE INSERT ON ports
FOR EACH ROW BEGIN
    SELECT CASE
        WHEN ((SELECT ip FROM hosts WHERE ip = NEW.ip) IS NULL)
        THEN RAISE(ABORT, 'insert on table "ports" violates foreign key constraint "fk_ports_hosts"')
    END;
END;

CREATE TRIGGER IF NOT EXISTS fku_ports_hosts_ip
BEFORE UPDATE ON ports
FOR EACH ROW BEGIN
    SELECT CASE
        WHEN ((SELECT ip FROM hosts WHERE ip = NEW.ip) IS NULL)
        THEN RAISE(ABORT, 'update on table "ports" violates foreign key constraint "fk_ports_hosts"')
    END;
END;

CREATE TRIGGER IF NOT EXISTS fkd_ports_hosts_ip
BEFORE DELETE ON hosts
FOR EACH ROW BEGIN
    DELETE from ports WHERE ip = OLD.ip;
END;


CREATE TRIGGER IF NOT EXISTS fki_smb_hosts_ip
BEFORE INSERT ON smb
FOR EACH ROW BEGIN
    SELECT CASE
        WHEN ((SELECT ip FROM hosts WHERE ip = NEW.ip) IS NULL)
        THEN RAISE(ABORT, 'insert on table "ports" violates foreign key constraint "fk_smb_hosts"')
    END;
END;

CREATE TRIGGER IF NOT EXISTS fku_smb_hosts_ip
BEFORE UPDATE ON smb
FOR EACH ROW BEGIN
    SELECT CASE
        WHEN ((SELECT ip FROM hosts WHERE ip = NEW.ip) IS NULL)
        THEN RAISE(ABORT, 'update on table "ports" violates foreign key constraint "fk_smb_hosts"')
    END;
END;

CREATE TRIGGER IF NOT EXISTS fkd_smb_hosts_ip
BEFORE DELETE ON hosts
FOR EACH ROW BEGIN
    DELETE from smb WHERE ip = OLD.ip;
END;




/* EOF */
