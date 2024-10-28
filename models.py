from flask_sqlalchemy import SQLAlchemy
import datetime
# from flask_uploads import UploadSet, IMAGES

db = SQLAlchemy()

class BaseModel(db.Model):
    """Base data model for all objects"""
    __abstract__ = True

    def __init__(self, *args):
        super().__init__(*args)

    def __repr__(self):
        """Define a base way to print models"""
        return '%s(%s)' % (self.__class__.__name__, {
            column: value
            for column, value in self._to_dict().items()
        })

    def json(self):
        """
                Define a base way to jsonify models, dealing with datetime objects
        """
        return {
            column: value if not isinstance(value, datetime.date) else value.strftime('%Y-%m-%d')
            for column, value in self._to_dict().items()
        }


class Transaction(BaseModel, db.Model):
    """Model for the transactions table"""
    __tablename__ = 'transactions'

    id = db.Column(db.Integer, primary_key=True)
    uname = db.Column(db.String)
    gw_sn = db.Column(db.String)
    gw_id = db.Column(db.String)
    ip = db.Column(db.String)
    gw_address = db.Column(db.String)
    gw_port = db.Column(db.String)
    mac = db.Column(db.String)
    apmac = db.Column(db.String)
    ssid = db.Column(db.String)
    vlanid = db.Column(db.String)
    token = db.Column(db.String)
    stage = db.Column(db.String)
    package = db.Column(db.String)
    device = db.Column(db.String)
    date_modified = db.Column(db.String)
    start_time = db.Column(db.DateTime(timezone=True))

    def __init__(self, **kwargs):
        self.id = kwargs.get('id')
        self.uname = kwargs.get('uname')
        self.gw_sn = kwargs.get('gw_sn')
        self.gw_id = kwargs.get('gw_id')
        self.ip = kwargs.get('ip')
        self.gw_address = kwargs.get('gw_address')
        self.gw_port = kwargs.get('gw_port')
        self.mac = kwargs.get('mac')
        self.apmac = kwargs.get('apmac')
        self.ssid = kwargs.get('ssid')
        self.vlanid = kwargs.get('vlanid')
        self.token = kwargs.get('token')
        self.stage = kwargs.get('stage')
        self.package = kwargs.get('package')
        self.device = kwargs.get('device')
        self.date_modified = kwargs.get('date_modified')
        self.start_time = kwargs.get('start_time')


class AccessAuthLogs(db.Model):
    """Model for capture & authenticated logs table"""
    __tablename__ = 'access_auth_logs'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)
    stage = db.Column(db.String)
    gw_id = db.Column(db.String)
    date = db.Column(db.DateTime, default=datetime.datetime.now)
    mac = db.Column(db.String)


class Devices(BaseModel, db.Model):
    """Model for the devices table"""
    __tablename__ = 'devices'

    id = db.Column(db.Integer, primary_key=True)
    mac = db.Column(db.String)
    free_data = db.Column(db.Float)
    month_data = db.Column(db.Float)
    last_record = db.Column(db.Float)
    last_active = db.Column(db.String)

    def __init__(self, **kwargs):
        self.id = kwargs.get('id')
        self.mac = kwargs.get('mac')
        self.free_data = kwargs.get('free_data')
        self.month_data = kwargs.get('month_data')
        self.last_record = kwargs.get('last_record')
        self.last_active = kwargs.get('last_active')


class Registered_Users(BaseModel, db.Model):
    """Model for the users table"""
    __tablename__ = 'registered_users'

    id = db.Column(db.Integer, primary_key=True)
    uname = db.Column(db.String)
    registered_data = db.Column(db.Float)
    month_data = db.Column(db.Float)
    last_record = db.Column(db.Float)
    last_active = db.Column(db.String)

    def __init__(self, **kwargs):
        self.id = kwargs.get('id')
        self.uname = kwargs.get('uname')
        self.registered_data = kwargs.get('registered_data')
        self.month_data = kwargs.get('month_data')
        self.last_record = kwargs.get('last_record')
        self.last_active = kwargs.get('last_active')


class CertifiedDevices(BaseModel, db.Model):
    """Model for the devices table"""
    __tablename__ = 'certified'

    id = db.Column(db.Integer, primary_key=True)
    mac = db.Column(db.String)
    common_name = db.Column(db.String)
    cert_data = db.Column(db.Float)
    month_data = db.Column(db.Float)
    last_record = db.Column(db.Float)
    last_active = db.Column(db.String)

    def __init__(self, **kwargs):
        self.id = kwargs.get('id')
        self.mac = kwargs.get('mac')
        self.common_name = kwargs.get('common_name')
        self.cert_data = kwargs.get('cert_data')
        self.month_data = kwargs.get('month_data')
        self.last_record = kwargs.get('last_record')
        self.last_active = kwargs.get('last_active')

class UserRoles(db.Model):
    """Model for the admin user roles table"""
    __tablename__ = 'roles'

    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String, unique=True)

    def __repr__(self):
        return self.role.title()

class Admin_Users(db.Model):
    """Model for the admin users table"""
    __tablename__ = 'admin_users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True)
    password = db.Column(db.String)
    first_name = db.Column(db.String)
    last_name = db.Column(db.String)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id', ondelete='RESTRICT'), nullable=False)
    role = db.relationship("UserRoles", foreign_keys=[role_id])
    mpop_id = db.Column(db.String, db.ForeignKey('gateways.gw_id', ondelete='RESTRICT'), nullable=False)
    mpop = db.relationship("Gateways", foreign_keys=[mpop_id])
    created_by_id = db.Column(db.Integer, db.ForeignKey('admin_users.id', ondelete='RESTRICT'))
    created_by = db.relationship("Admin_Users", foreign_keys=[created_by_id], remote_side=id)
    created_on = db.Column(db.String, default=datetime.datetime.now)
    modified_by_id = db.Column(db.Integer, db.ForeignKey('admin_users.id', ondelete='RESTRICT'))
    modified_by = db.relationship("Admin_Users", foreign_keys=[modified_by_id], remote_side=id)
    modified_on = db.Column(db.String, default=datetime.datetime.now, onupdate=datetime.datetime.now)
    # gateways = db.relationship(
    #     "Gateways", backref="modified_by", lazy="dynamic", foreign_keys=[])
    # uptimes = db.relationship(
    #     "Uptimes", backref="modified_by", lazy="dynamic")
    # announcements = db.relationship(
    #     "Announcements", backref="modified_by", lazy="dynamic")
    # logos = db.relationship(
    #     "Logos", backref="modified_by", lazy="dynamic")

    def __init__(self, **kwargs):
        self.id = kwargs.get('id')
        self.username = kwargs.get('username')
        self.password = kwargs.get('password')
        self.first_name = kwargs.get('first_name')
        self.last_name = kwargs.get('last_name')

    # Flask-Login integration
    # NOTE: is_authenticated, is_active, and is_anonymous
    # are methods in Flask-Login < 0.3.0
    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    def get_mpop_id(self):
        return self.mpop_id

    def get_role(self):
        return self.role_id

    # Required for administrative interface
    def __unicode__(self):
        return self.username

    def __repr__(self):
        return self.username

class GatewayGroup(db.Model):
    """Model for the mpop groups table"""
    __tablename__ = 'gateway_group'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True)
    status = db.Column(db.SmallInteger)
    created_by_id = db.Column(db.Integer, db.ForeignKey('admin_users.id', ondelete='RESTRICT'), nullable=False)
    created_by = db.relationship("Admin_Users", foreign_keys=[created_by_id])
    created_on = db.Column(db.String, default=datetime.datetime.now)
    modified_by_id = db.Column(db.Integer, db.ForeignKey('admin_users.id', ondelete='RESTRICT'), nullable=False)
    modified_by = db.relationship("Admin_Users", foreign_keys=[modified_by_id])
    modified_on = db.Column(db.String, default=datetime.datetime.now, onupdate=datetime.datetime.now)

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.id

class Gateways(db.Model):
    """Model for the mpop ids table"""
    __tablename__ = 'gateways'

    id = db.Column(db.Integer, primary_key=True)
    gw_id = db.Column(db.String, unique=True)
    name = db.Column(db.String, unique=True)
    status = db.Column(db.SmallInteger)
    created_by_id = db.Column(db.Integer, db.ForeignKey('admin_users.id', ondelete='RESTRICT'), nullable=False)
    created_by = db.relationship("Admin_Users", foreign_keys=[created_by_id])
    created_on = db.Column(db.String)
    modified_by_id = db.Column(db.Integer, db.ForeignKey('admin_users.id', ondelete='RESTRICT'), nullable=False)
    modified_by = db.relationship("Admin_Users", foreign_keys=[modified_by_id])
    modified_on = db.Column(
        db.String, default=datetime.datetime.now, onupdate=datetime.datetime.now)
    limits = db.relationship(
        "Data_Limits", backref="gateway_id", lazy="dynamic", passive_deletes='all')
    uptimes = db.relationship(
        "Uptimes", backref="gateway_id", lazy="dynamic", passive_deletes='all')
    redirects = db.relationship(
        "PortalRedirectLinks", backref="gateway_id", lazy="dynamic", passive_deletes='all')
    announcements = db.relationship(
        "Announcements", backref="gateway_id", lazy="dynamic", passive_deletes='all')
    logos = db.relationship(
        "Logos", backref="gateway_id", lazy="dynamic", passive_deletes='all')
    groups = db.relationship('GatewayGroup', secondary="gateway_groups",backref=db.backref('gateways'))

    def get_gw_id(self):
        return self.gw_id

    def __repr__(self):
        return self.gw_id

class GatewayGroups(db.Model):
    __tablename__="gateway_groups"
    
    id = db.Column(db.Integer(), primary_key=True)
    gw_id = db.Column(db.String(), db.ForeignKey('gateways.gw_id', ondelete='RESTRICT'), nullable=False)
    gateway = db.relationship("Gateways", foreign_keys=[gw_id])
    group_id = db.Column(db.Integer(), db.ForeignKey('gateway_group.id', ondelete='RESTRICT'), nullable=False)
    group = db.relationship("GatewayGroup", foreign_keys=[group_id])

class Data_Limits(db.Model):
    """Model for the data limits table"""
    __tablename__ = 'data_limits'

    id = db.Column(db.Integer, primary_key=True)
    access_type = db.Column(db.SmallInteger)
    limit_type = db.Column(db.String(2))
    gw_id = db.Column(db.String, db.ForeignKey(
        'gateways.gw_id', ondelete='RESTRICT'), nullable=False)
    value = db.Column(db.Float)
    status = db.Column(db.SmallInteger, default=0)
    created_by_id = db.Column(db.Integer, db.ForeignKey('admin_users.id', ondelete='RESTRICT'), nullable=False)
    created_by = db.relationship("Admin_Users", foreign_keys=[created_by_id])
    created_on = db.Column(db.String)
    modified_by_id = db.Column(db.Integer, db.ForeignKey('admin_users.id', ondelete='RESTRICT'), nullable=False)
    modified_by = db.relationship("Admin_Users", foreign_keys=[modified_by_id])
    modified_on = db.Column(
        db.String, default=datetime.datetime.now, onupdate=datetime.datetime.now)

    __table_args__ = (db.UniqueConstraint(
        'gw_id', 'access_type', 'limit_type'), )


class Uptimes(db.Model):
    """Model for the portal uptimes table"""
    __tablename__ = 'uptimes'

    id = db.Column(db.Integer, primary_key=True)
    gw_id = db.Column(db.String, db.ForeignKey(
        'gateways.gw_id', ondelete='RESTRICT'), unique=True, nullable=False)
    start_time = db.Column(db.Time(timezone=False))
    end_time = db.Column(db.Time(timezone=False))
    status = db.Column(db.SmallInteger, default=0)
    modified_by_id = db.Column(db.Integer, db.ForeignKey('admin_users.id', ondelete='RESTRICT'), nullable=False)
    modified_by = db.relationship("Admin_Users", foreign_keys=[modified_by_id])
    modified_on = db.Column(
        db.String, default=datetime.datetime.now, onupdate=datetime.datetime.now)
    created_by_id = db.Column(db.Integer, db.ForeignKey('admin_users.id', ondelete='RESTRICT'), nullable=False)
    created_by = db.relationship("Admin_Users", foreign_keys=[created_by_id])
    created_on = db.Column(db.String)


class PortalRedirectLinks(db.Model):
    """Model for the portal uptimes table"""
    __tablename__ = 'redirect_links'

    id = db.Column(db.Integer, primary_key=True)
    gw_id = db.Column(db.String, db.ForeignKey(
        'gateways.gw_id', ondelete='RESTRICT'), unique=True, nullable=False)
    url = db.Column(db.String)
    status = db.Column(db.SmallInteger, default=0)
    modified_by_id = db.Column(db.Integer, db.ForeignKey('admin_users.id', ondelete='RESTRICT'), nullable=False)
    modified_by = db.relationship("Admin_Users", foreign_keys=[modified_by_id])
    modified_on = db.Column(db.String, default=datetime.datetime.now, onupdate=datetime.datetime.now)
    created_by_id = db.Column(db.Integer, db.ForeignKey('admin_users.id', ondelete='RESTRICT'), nullable=False)
    created_by = db.relationship("Admin_Users", foreign_keys=[created_by_id])
    created_on = db.Column(db.String)


# images = UploadSet('images', IMAGES)


# class Announcements(db.Model):
#     """Model for the announcement images table"""
#     __tablename__ = 'announcements'

#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.Unicode(64))
#     path = db.Column(db.Unicode(128))
#     status = db.Column(db.SmallInteger, default=0)
#     gw_id = db.Column(db.String, db.ForeignKey(
#         'gateways.gw_id', ondelete='RESTRICT'), unique=True, nullable=False)
#     modified_by_id = db.Column(db.Integer, db.ForeignKey('admin_users.id', ondelete='RESTRICT'), nullable=False)
#     modified_by = db.relationship("Admin_Users", foreign_keys=[modified_by_id])
#     modified_on = db.Column(
#         db.String, default=datetime.datetime.now, onupdate=datetime.datetime.now)
#     created_by_id = db.Column(db.Integer, db.ForeignKey('admin_users.id', ondelete='RESTRICT'), nullable=False)
#     created_by = db.relationship("Admin_Users", foreign_keys=[created_by_id])
#     created_on = db.Column(db.String,default=datetime.datetime.now)

#     def __unicode__(self):
#         return self.name

#     @property
#     def url(self):
#         return images.url(self.path)

#     @property
#     def filepath(self):
#         if self.path is None:
#             return
#         return images.path(self.path)


# class GroupAnnouncements(db.Model):
#     """Model for the announcement images table"""
#     __tablename__ = 'group_announcements'

#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.Unicode(64))
#     path = db.Column(db.Unicode(128))
#     status = db.Column(db.SmallInteger, default=0)
#     group_id = db.Column(db.Integer, db.ForeignKey(
#         'gateway_group.id', ondelete='RESTRICT'), unique=True, nullable=False)
#     group = db.relationship("GatewayGroup", foreign_keys=[group_id])
#     modified_by_id = db.Column(db.Integer, db.ForeignKey('admin_users.id', ondelete='RESTRICT'), nullable=False)
#     modified_by = db.relationship("Admin_Users", foreign_keys=[modified_by_id])
#     modified_on = db.Column(
#         db.String, default=datetime.datetime.now, onupdate=datetime.datetime.now)
#     created_by_id = db.Column(db.Integer, db.ForeignKey('admin_users.id', ondelete='RESTRICT'), nullable=False)
#     created_by = db.relationship("Admin_Users", foreign_keys=[created_by_id])
#     created_on = db.Column(db.String)

#     def __unicode__(self):
#         return self.name

#     @property
#     def url(self):
#         return images.url(self.path)

#     @property
#     def filepath(self):
#         if self.path is None:
#             return
#         return images.path(self.path)


# class Logos(db.Model):
#     """Model for the logo images table"""
#     __tablename__ = 'logos'

#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.Unicode(64))
#     path = db.Column(db.Unicode(128))
#     status = db.Column(db.SmallInteger, default=0)
#     gw_id = db.Column(db.String, db.ForeignKey(
#         'gateways.gw_id', ondelete='RESTRICT'), unique=True, nullable=False)
#     modified_by_id = db.Column(db.Integer, db.ForeignKey('admin_users.id', ondelete='RESTRICT'), nullable=False)
#     modified_by = db.relationship("Admin_Users", foreign_keys=[modified_by_id])
#     modified_on = db.Column(
#         db.String, default=datetime.datetime.now, onupdate=datetime.datetime.now)
#     created_by_id = db.Column(db.Integer, db.ForeignKey('admin_users.id', ondelete='RESTRICT'), nullable=False)
#     created_by = db.relationship("Admin_Users", foreign_keys=[created_by_id])
#     created_on = db.Column(db.String)

#     def __unicode__(self):
#         return self.name

#     @property
#     def url(self):
#         return images.url(self.path)

#     @property
#     def filepath(self):
#         if self.path is None:
#             return
#         return images.path(self.path)


class RegisterUser(db.Model):
    """Model for the free radius registered users table"""
    __tablename__ = 'subscribers'
    __bind_key__ = 'radius'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String)
    # attribute = db.Column(db.String, default='Cleartext-Password')
    # op = db.Column(db.String, default=':=')
    password = db.Column(db.String)
    fname = db.Column(db.String)
    lname = db.Column(db.String)
    mname = db.Column(db.String)
    ename = db.Column(db.String)
    address = db.Column(db.String)
    phone_no = db.Column(db.String)
    birthdate = db.Column(db.Date)
    gender = db.Column(db.String(2))
    id_type = db.Column(db.String(2))
    id_value = db.Column(db.String)
    status = db.Column(db.SmallInteger)
    token = db.Column(db.String)
    registration_date = db.Column(db.String)
    validated = db.Column(db.SmallInteger)


class Accounting(db.Model):
    """Model for the radius accounting table"""
    __tablename__ = 'accounting'
    __bind_key__ = 'radius'

    username = db.Column(db.String, primary_key=True)
    time_stamp = db.Column(db.BigInteger, primary_key=True)
    acctstatustype = db.Column(db.String)
    acctsessionid = db.Column(db.BigInteger)
    nasidentifier = db.Column(db.String)
    auth_mode = db.Column(db.String)
    device = db.Column(db.String)
    acctinputoctets = db.Column(db.BigInteger)
    acctoutputoctets = db.Column(db.BigInteger)
    framedipaddress = db.Column(db.String)
    mac = db.Column(db.String)
    created_at = db.Column(db.DateTime(timezone=True))

class SessionId(db.Model):
    """Model for the radius accounting table"""
    __tablename__ = 'session_ids'

    session_id = db.Column(db.String, primary_key=True)
    mac = db.Column(db.String, unique=True, nullable=False)