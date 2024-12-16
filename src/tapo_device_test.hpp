
// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

void test_P11x (const tapo::DeviceConfig& config) {
    WiFiClient client;
    tapo::P11x device (config, client);

    auto [connect_success, connect_error] = device.connect ();
    if (! connect_success) {
        Serial.printf ("Failed to connect: %s\n", connect_error.c_str ());
        esp_restart ();
    }

    Serial.printf ("\n///\n");
    auto [device_info_success, device_info_details] = device.get_device_info ();
    if (device_info_success)
        Serial.println ("Device Info: " + device_info_details.toString ());
    Serial.printf ("\n///\n");
    auto [device_usage_success, device_usage_details] = device.get_device_usage ();
    if (device_usage_success)
        Serial.println ("Device Usage: " + device_usage_details.toString ());
    Serial.printf ("\n///\n");
    auto [device_power_success, device_power_details] = device.get_current_power ();
    if (device_power_success)
        Serial.println ("Current Power: " + device_power_details.toString ());
    Serial.printf ("\n///\n");
    auto [device_energy_usage_success, device_energy_usage_details] = device.get_energy_usage ();
    if (device_energy_usage_success)
        Serial.println ("Energy Usage: " + device_energy_usage_details.toString ());
    Serial.printf ("\n///\n");
    auto [device_energy_data_success, device_energy_data_details] = device.get_energy_data (time (nullptr) - 24 * 3600, time (nullptr), 60);
    if (device_energy_data_success)
        Serial.println ("Energy Data: " + device_energy_data_details.toString ());
    Serial.printf ("\n///\n");

    auto [device_power_set_success, device_power_set_details] = device.set_power (true);
    if (device_power_set_success)
        Serial.println ("Power Set: " + device_power_set_details.toString ());
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------

void test_P10x (const tapo::DeviceConfig& config) {
    WiFiClient client;
    tapo::P10x device (config, client);

    auto [connect_success, connect_error] = device.connect ();
    if (! connect_success) {
        Serial.printf ("Failed to connect: %s\n", connect_error.c_str ());
        esp_restart ();
    }

    Serial.printf ("\n///\n");
    auto [device_info_success, device_info_details] = device.get_device_info ();
    if (device_info_success)
        Serial.println ("Device Info: " + device_info_details.toString ());
    Serial.printf ("\n///\n");
    auto [device_usage_success, device_usage_details] = device.get_device_usage ();
    if (device_usage_success)
        Serial.println ("Device Usage: " + device_usage_details.toString ());

    auto [device_power_set_success, device_power_set_details] = device.set_power (true);
    if (device_power_set_success)
        Serial.println ("Power Set: " + device_power_set_details.toString ());
}


// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------
