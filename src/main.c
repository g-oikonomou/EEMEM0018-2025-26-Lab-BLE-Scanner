/* main.c - Application main entry point */

/*
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/types.h>
#include <stddef.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/util.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/sys/byteorder.h>

// Define Manufacturer Specific Data structure
struct adv_mfg_data {
	uint16_t company_id;
	int16_t temperature;
	uint8_t group_id;
} __packed;
typedef struct adv_mfg_data adv_mfg_data_t;

// This is our device name from prj.conf
#define DEVICE_NAME CONFIG_BT_DEVICE_NAME
#define DEVICE_NAME_LEN (sizeof(DEVICE_NAME) - 1)

// This is the company ID that will be in the Manufacturer Specific Data
#define COMPANY_ID 0x0059 // Nordic Semiconductor ASA

// Initialise data to be advertised
static adv_mfg_data_t adv_mfg_data = {
	.company_id = COMPANY_ID,
	.temperature = 0,
	.group_id = 99, // Default silly group ID 
};

/**
 * Our advertisement data structure.
 * 
 * We include the device name and the manufacturer specific data (which includes specific company ID and temperature sensor value).
 */
static const struct bt_data ad[] = {
	BT_DATA(BT_DATA_NAME_COMPLETE, DEVICE_NAME, DEVICE_NAME_LEN),
	BT_DATA(BT_DATA_MANUFACTURER_DATA, (uint8_t *)&adv_mfg_data, sizeof(adv_mfg_data)),
};

// Now it's time for advertisement parameters
static const struct bt_le_adv_param *adv_param = BT_LE_ADV_PARAM(
	BT_LE_ADV_OPT_NONE,
	BT_GAP_ADV_SLOW_INT_MIN,
	BT_GAP_ADV_SLOW_INT_MIN,
	NULL
);


int main(void)
{
	int err;

	float temperature = 25.1f;
	bool increasing = true;

	printk("Starting Scanner/Advertiser Demo\n");

	/* Initialize the Bluetooth Subsystem */
	err = bt_enable(NULL);
	if (err) {
		printk("Bluetooth init failed (err %d)\n", err);
		return 0;
	}

	printk("Bluetooth initialized\n");

	err = bt_le_adv_start(adv_param, ad, ARRAY_SIZE(ad), NULL, 0);
	if (err)
	{
		printk("Advertising failed to start (err %d)\n", err);
		return 0;
	}

	while(1)
	{
		// Simulate temperature change
		if (increasing)
		{
			temperature += 0.2f;
			if (temperature >= 30.0f)
			{
				increasing = false;
			}
		}
		else
		{
			temperature -= 0.2f;
			if (temperature <= 20.0f)
			{
				increasing = true;
			}
		}

		int16_t temp_int16 = (int16_t)(temperature * 100);

		// Update the temperature in the advertisement data
		adv_mfg_data.temperature = sys_cpu_to_le16(temp_int16);

		// Update your group ID here
		adv_mfg_data.group_id = 2; // Example group ID

		err = bt_le_adv_update_data(ad, ARRAY_SIZE(ad), NULL, 0);
		if (err) {
			printk("Failed to update advertising data (err %d)\n", err);
		}

		k_sleep(K_MSEC(500));
	} 

	return 0;
}
