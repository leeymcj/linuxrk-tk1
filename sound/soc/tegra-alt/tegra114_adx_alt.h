/*
 * tegra114_adx_alt.h - Definitions for Tegra114 ADX driver
 *
 * Copyright (c) 2013, NVIDIA CORPORATION.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __TEGRA114_ADX_ALT_H__
#define __TEGRA114_ADX_ALT_H__

#define TEGRA_ADX_AUDIOCIF_CH_STRIDE 4

/* Register offsets from ADX*_BASE */
#define TEGRA_ADX_CTRL			0x00
#define TEGRA_ADX_OUT_CH_CTRL			0x04
#define TEGRA_ADX_IN_BYTE_EN0			0x08
#define TEGRA_ADX_IN_BYTE_EN1			0x0c
#define TEGRA_ADX_AUDIORAMCTL_ADX_CTRL	0x10
#define TEGRA_ADX_AUDIORAMCTL_ADX_DATA	0x14
#define TEGRA_ADX_AUDIOCIF_IN_CTRL		0x18
#define TEGRA_ADX_AUDIOCIF_CH0_CTRL		0x1c
#define TEGRA_ADX_AUDIOCIF_CH1_CTRL		0x20
#define TEGRA_ADX_AUDIOCIF_CH2_CTRL		0x24
#define TEGRA_ADX_AUDIOCIF_CH3_CTRL		0x28

/* Fields inTEGRA_ADX_CTRL */
#define TEGRA_ADX_CTRL_SOFT_RESET_SHIFT	31
#define TEGRA_ADX_CTRL_CG_EN_SHIFT		30

/* Fields inTEGRA_ADX_OUT_CH_CTRL */
#define TEGRA_ADX_OUT_CH_ENABLE	1
#define TEGRA_ADX_OUT_CH_DISABLE	0
#define TEGRA_ADX_OUT_CH_CTRL_CH3_FORCE_DISABLE_SHIFT		11
#define TEGRA_ADX_OUT_CH_CTRL_CH2_FORCE_DISABLE_SHIFT		10
#define TEGRA_ADX_OUT_CH_CTRL_CH1_FORCE_DISABLE_SHIFT		9
#define TEGRA_ADX_OUT_CH_CTRL_CH0_FORCE_DISABLE_SHIFT		8
#define TEGRA_ADX_OUT_CH_CTRL_CH3_DISABLE_SHIFT		3
#define TEGRA_ADX_OUT_CH_CTRL_CH2_DISABLE_SHIFT		2
#define TEGRA_ADX_OUT_CH_CTRL_CH1_DISABLE_SHIFT		1
#define TEGRA_ADX_OUT_CH_CTRL_CH0_DISABLE_SHIFT		0

/* Fields inTEGRA_ADX_AUDIORAMCTL_ADX_CTRL */
#define TEGRA_ADX_AUDIORAMCTL_ADX_CTRL_RAM_ADR_SHIFT		0
#define TEGRA_ADX_AUDIORAMCTL_ADX_CTRL_HW_ADR_EN_SHIFT	12
#define TEGRA_ADX_AUDIORAMCTL_ADX_CTRL_RESET_HW_ADR_SHIFT	13
#define TEGRA_ADX_AUDIORAMCTL_ADX_CTRL_RW_SHIFT		14
#define TEGRA_ADX_AUDIORAMCTL_ADX_CTRL_READ_BUSY_SHIFT	31

#define TEGRA_ADX_AUDIORAMCTL_ADX_CTRL_HW_ADR_EN_ENABLE	(1 << TEGRA_ADX_AUDIORAMCTL_ADX_CTRL_HW_ADR_EN_SHIFT)
#define TEGRA_ADX_AUDIORAMCTL_ADX_CTRL_HW_ADR_EN_DISABLE	0
#define TEGRA_ADX_AUDIORAMCTL_ADX_CTRL_RW_READ		0
#define TEGRA_ADX_AUDIORAMCTL_ADX_CTRL_RW_WRITE		(1 << TEGRA_ADX_AUDIORAMCTL_ADX_CTRL_RW_SHIFT)

/*
 * Those defines are not in register field.
 */
#define TEGRA_ADX_RAM_DEPTH			16
#define TEGRA_ADX_MAP_STREAM_NUMBER_SHIFT	6
#define TEGRA_ADX_MAP_WORD_NUMBER_SHIFT	2
#define TEGRA_ADX_MAP_BYTE_NUMBER_SHIFT	0

/* Fields in TEGRA_ADX_AUDIOCIF_IN_CTRL */
/* Uses field from AUDIOCIF_CTRL_* in tegra_cif_utils_alt.h */

/* Fields in TEGRA_ADX_AUDIOCIF_CH0_CTRL */
/* Uses field from AUDIOCIF_CTRL_* in tegra_cif_utils_alt.h */

/* Fields in TEGRA_ADX_AUDIOCIF_CH1_CTRL */
/* Uses field from AUDIOCIF_CTRL_* in tegra_cif_utils_alt.h */

/* Fields in TEGRA_ADX_AUDIOCIF_CH2_CTRL */
/* Uses field from AUDIOCIF_CTRL_* in tegra_cif_utils_alt.h */

/* Fields in TEGRA_ADX_AUDIOCIF_CH3_CTRL */
/* Uses field from AUDIOCIF_CTRL_* in tegra_cif_utils_alt.h */

enum {
	/* Code assumes that OUT_STREAM values of ADX start at 0 */
	/* OUT_STREAM# is equilvant to hw OUT_CH# */
	TEGRA_ADX_OUT_STREAM0 = 0,
	TEGRA_ADX_OUT_STREAM1,
	TEGRA_ADX_OUT_STREAM2,
	TEGRA_ADX_OUT_STREAM3,
	TEGRA_ADX_IN_STREAM,
	TEGRA_ADX_TOTAL_STREAM
};

struct tegra114_adx_soc_data {
	void (*set_audio_cif)(struct regmap *map,
			unsigned int reg,
			struct tegra30_xbar_cif_conf *conf);
};

struct tegra114_adx {
	struct clk *clk_adx;
	struct regmap *regmap;
	unsigned int map[16];
	const struct tegra114_adx_soc_data *soc_data;
};

#endif
