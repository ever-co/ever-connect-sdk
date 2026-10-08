import { Routes } from '@angular/router';
import { FeaturesComponent, GeneralComponent } from './settings.components';

export const settingsRoutes: Routes = [
	{ path: '', redirectTo: 'general', pathMatch: 'full' },
	{ path: 'general', component: GeneralComponent },
	{ path: 'features', component: FeaturesComponent }
];
