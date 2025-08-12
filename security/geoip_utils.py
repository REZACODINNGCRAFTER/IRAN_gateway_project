# security/geoip_utils.py

import geoip2.database
import geoip2.errors
import logging
from django.conf import settings
from ipaddress import ip_address as ip_check, IPv4Address, IPv6Address

logger = logging.getLogger(__name__)

GEOIP_DB_PATH = getattr(settings, 'GEOIP_DB_PATH', '/etc/geoip/GeoLite2-City.mmdb')

class GeoIPService:
    def __init__(self, db_path=GEOIP_DB_PATH):
        try:
            self.reader = geoip2.database.Reader(db_path)
        except Exception as e:
            logger.error(f"Failed to load GeoIP2 database: {e}")
            self.reader = None

    def get_location(self, ip_address):
        if not self.reader:
            return None
        try:
            response = self.reader.city(ip_address)
            return {
                'country': response.country.name,
                'country_code': response.country.iso_code,
                'region': response.subdivisions.most_specific.name,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
                'timezone': response.location.time_zone,
                'postal_code': response.postal.code,
                'continent': response.continent.name,
            }
        except geoip2.errors.AddressNotFoundError:
            logger.warning(f"GeoIP address not found: {ip_address}")
            return None
        except Exception as e:
            logger.error(f"GeoIP lookup failed for {ip_address}: {e}")
            return None

    def is_supported_country(self, ip_address, allowed_countries):
        location = self.get_location(ip_address)
        if location:
            return location.get('country') in allowed_countries or location.get('country_code') in allowed_countries
        return False

    def get_country_code(self, ip_address):
        if not self.reader:
            return None
        try:
            response = self.reader.city(ip_address)
            return response.country.iso_code
        except Exception as e:
            logger.error(f"Country code lookup failed for {ip_address}: {e}")
            return None

    def get_timezone(self, ip_address):
        location = self.get_location(ip_address)
        return location.get('timezone') if location else None

    def get_coordinates(self, ip_address):
        location = self.get_location(ip_address)
        if location:
            return (location.get('latitude'), location.get('longitude'))
        return None

    def get_city(self, ip_address):
        location = self.get_location(ip_address)
        return location.get('city') if location else None

    def get_region(self, ip_address):
        location = self.get_location(ip_address)
        return location.get('region') if location else None

    def get_postal_code(self, ip_address):
        location = self.get_location(ip_address)
        return location.get('postal_code') if location else None

    def get_continent(self, ip_address):
        location = self.get_location(ip_address)
        return location.get('continent') if location else None

    def is_valid_ip(self, ip_str):
        try:
            ip_check(ip_str)
            return True
        except ValueError:
            return False

    def is_ipv4(self, ip_str):
        try:
            return isinstance(ip_check(ip_str), IPv4Address)
        except ValueError:
            return False

    def is_ipv6(self, ip_str):
        try:
            return isinstance(ip_check(ip_str), IPv6Address)
        except ValueError:
            return False

    def is_europe(self, ip_address):
        continent = self.get_continent(ip_address)
        return continent == 'Europe'

    def is_from_timezone(self, ip_address, timezone):
        tz = self.get_timezone(ip_address)
        return tz == timezone

    def is_city_match(self, ip_address, city):
        location_city = self.get_city(ip_address)
        return location_city and location_city.lower() == city.lower()

    def is_postal_code_match(self, ip_address, postal_code):
        location_postal = self.get_postal_code(ip_address)
        return location_postal == postal_code

    def is_in_lat_lon_range(self, ip_address, lat_min, lat_max, lon_min, lon_max):
        coords = self.get_coordinates(ip_address)
        if coords:
            lat, lon = coords
            return lat_min <= lat <= lat_max and lon_min <= lon <= lon_max
        return False

    def is_from_country_code(self, ip_address, country_code):
        code = self.get_country_code(ip_address)
        return code == country_code

    def is_region_match(self, ip_address, region):
        region_name = self.get_region(ip_address)
        return region_name and region_name.lower() == region.lower()

    def get_full_address(self, ip_address):
        location = self.get_location(ip_address)
        if location:
            return f"{location.get('city', '')}, {location.get('region', '')}, {location.get('country', '')}"
        return None

    def is_within_radius(self, ip_address, center_lat, center_lon, radius_km):
        from math import radians, cos, sin, asin, sqrt
        coords = self.get_coordinates(ip_address)
        if not coords:
            return False
        lat1, lon1 = coords
        lat2, lon2 = center_lat, center_lon

        # Haversine formula
        dlat = radians(lat2 - lat1)
        dlon = radians(lon2 - lon1)
        a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
        c = 2 * asin(sqrt(a))
        earth_radius_km = 6371
        distance = earth_radius_km * c
        return distance <= radius_km

    def close(self):
        if self.reader:
            self.reader.close()

# Singleton instance
_geoip_service = GeoIPService()

def lookup_ip(ip):
    return _geoip_service.get_location(ip)

def get_country_code(ip):
    return _geoip_service.get_country_code(ip)

def get_timezone(ip):
    return _geoip_service.get_timezone(ip)

def get_coordinates(ip):
    return _geoip_service.get_coordinates(ip)

def get_city(ip):
    return _geoip_service.get_city(ip)

def get_region(ip):
    return _geoip_service.get_region(ip)

def get_postal_code(ip):
    return _geoip_service.get_postal_code(ip)

def get_continent(ip):
    return _geoip_service.get_continent(ip)

def is_ip_valid(ip):
    return _geoip_service.is_valid_ip(ip)

def is_ipv4(ip):
    return _geoip_service.is_ipv4(ip)

def is_ipv6(ip):
    return _geoip_service.is_ipv6(ip)

def is_allowed_country(ip, country_list):
    return _geoip_service.is_supported_country(ip, country_list)

def is_europe(ip):
    return _geoip_service.is_europe(ip)

def is_timezone(ip, timezone):
    return _geoip_service.is_from_timezone(ip, timezone)

def is_city(ip, city):
    return _geoip_service.is_city_match(ip, city)

def is_postal(ip, postal_code):
    return _geoip_service.is_postal_code_match(ip, postal_code)

def is_in_region_bounds(ip, lat_min, lat_max, lon_min, lon_max):
    return _geoip_service.is_in_lat_lon_range(ip, lat_min, lat_max, lon_min, lon_max)

def is_country_code(ip, country_code):
    return _geoip_service.is_from_country_code(ip, country_code)

def is_region(ip, region):
    return _geoip_service.is_region_match(ip, region)

def get_full_address(ip):
    return _geoip_service.get_full_address(ip)

def is_within_radius(ip, center_lat, center_lon, radius_km):
    return _geoip_service.is_within_radius(ip, center_lat, center_lon, radius_km)

def close_reader():
    _geoip_service.close()
